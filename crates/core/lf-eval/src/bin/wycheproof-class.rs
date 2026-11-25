//! Prints how `lf-eval` ends each Wycheproof test of `scripts/gen-wycheproof-secp.py`, one `<tcId>\t<outcome>` per line.
//!
//!   wycheproof-class <dar> <vectors.tsv>
//!
//! `outcome` is `ok:True`, `ok:False` or `fatal:<error>` (an error that is not a Daml exception: on the JVM it ends the whole
//! `daml script` process). `scripts/verify-wycheproof.sh` uses this to decide which tests can share one JVM process and which
//! need one process each. The classification only chooses how to RUN the JVM; the JVM's own answer is what is recorded.
use std::process::ExitCode;

use lf_eval::{Value, World};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: wycheproof-class <dar> <vectors.tsv>");
        return ExitCode::from(2);
    }
    let world = match World::open(std::path::Path::new(&args[1])) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("cannot open {}: {e}", args[1]);
            return ExitCode::from(1);
        }
    };
    let table = match std::fs::read_to_string(&args[2]) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cannot read {}: {e}", args[2]);
            return ExitCode::from(1);
        }
    };
    for line in table.lines() {
        let Some(tc) = line.split('\t').next().filter(|t| !t.is_empty()) else {
            continue;
        };
        let outcome = match world.eval("Wy", &format!("c{tc}"), &[]) {
            Ok(Value::Bool(true)) => "ok:True".to_string(),
            Ok(Value::Bool(false)) => "ok:False".to_string(),
            Ok(other) => format!("fatal:unexpected value {other:?}"),
            Err(e) => format!("fatal:{e}").replace('\n', " "),
        };
        println!("{tc}\t{outcome}");
    }
    ExitCode::SUCCESS
}
