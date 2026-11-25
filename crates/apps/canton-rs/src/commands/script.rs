//! Daml Script runner (`canton-rs script`) (G10, AT-K06, S-SCRIPT-002).
//!
//! Runs a `Script a` of a compiled `.dar` the way `daml script --dar <DAR> --script-name <Module:Name>` does:
//! - `--ide-ledger`: on the in-memory IDE ledger of [`lf_eval::script::ScriptHost`] (static time from the epoch), the same ledger the official
//!   runner's `--ide-ledger --static-time` uses (checked against its recorded outputs, `tests/oracle/script-host`);
//! - `--ledger-host`/`--ledger-port`: against a participant's JSON Ledger API v2 (see [`crate::commands::script_remote`]).
//!
//! The result is written as `daml script --output-file` writes it (compact JSON); an exception the script does not catch ends the run with
//! the official runner's message and a non-zero exit.
//!
//! [CANTON-NOTE: WHY] This command used to answer a fixed list of scenario names (`createOk`, `splitOk`, ...) from a hard-coded ledger model
//! whatever the DAR contained, and to evaluate any other name as a plain value: a script that did not exist "succeeded". It now runs
//! only what the DAR defines.

use std::path::Path;

use clap::Args;

#[derive(Args, Debug)]
pub struct ScriptArgs {
    /// Path to the compiled `.dar` archive file (`--dar`).
    #[arg(long)]
    pub dar: String,

    /// The script to run, `Module:Name` (`--script-name`).
    #[arg(long)]
    pub script_name: String,

    /// Run on the in-memory IDE ledger (`--ide-ledger`).
    #[arg(long, default_value_t = false, conflicts_with = "ledger_host")]
    pub ide_ledger: bool,

    /// Run against the JSON Ledger API v2 of a participant at this host.
    #[arg(long, requires = "ledger_port")]
    pub ledger_host: Option<String>,

    /// The port of that JSON Ledger API.
    #[arg(long, requires = "ledger_host")]
    pub ledger_port: Option<u16>,

    /// The user the commands are submitted as on a remote ledger (`userId` of the JSON API).
    #[arg(long, default_value = "participant_admin")]
    pub user_id: String,

    /// Accepted for compatibility with `daml script`: the IDE ledger always runs on static time from the epoch.
    #[arg(long, default_value_t = false)]
    pub static_time: bool,

    /// Write the script's result here as compact JSON (`--output-file`).
    #[arg(long)]
    pub output_file: Option<String>,
}

pub fn execute_script(args: ScriptArgs) -> Result<(), String> {
    let dar_path = Path::new(&args.dar);
    let world = lf_eval::World::open(dar_path)
        .map_err(|e| format!("Failed to load DAR '{}': {e}", args.dar))?;
    let (module, name) = args.script_name.rsplit_once(':').ok_or_else(|| {
        format!(
            "--script-name must be Module:Name, got '{}'",
            args.script_name
        )
    })?;

    let result = if args.ide_ledger {
        lf_eval::script::ScriptHost::new(&world).run(module, name)
    } else if let (Some(host), Some(port)) = (&args.ledger_host, args.ledger_port) {
        let ledger =
            crate::commands::script_remote::JsonApiLedger::new(host, port, &args.user_id, &world)?;
        lf_eval::script::ScriptHost::remote(&world, Box::new(ledger)).run(module, name)
    } else {
        return Err("either --ide-ledger or --ledger-host/--ledger-port is required".into());
    };

    let value = match result {
        Ok(v) => v,
        // the official runner dies with the interpretation error's message
        Err(lf_eval::script::ScriptError::Eval(message)) => return Err(message),
        Err(other) => return Err(other.to_string()),
    };
    // printed by the script's declared type (`Script a`), as the official runner does: a `Time` is a date-time, an `Int` a number
    let types = lf_eval::typed_json::Types::new(&world);
    let json = types
        .value_type(world.main_package_id(), module, name)
        .and_then(|ty| types.encode_script_result(&ty, &value))
        .map_err(|e| format!("cannot print the result of {}: {e}", args.script_name))?
        .to_string();
    if let Some(path) = &args.output_file {
        std::fs::write(path, &json).map_err(|e| format!("cannot write {path}: {e}"))?;
    }
    println!("{json}");
    Ok(())
}
