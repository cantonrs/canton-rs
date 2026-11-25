use std::env;
use std::path::Path;
use std::process::ExitCode;

use lf_eval::{parse_arg, render, World};

fn open_world(dar: &str, allow_dev: bool) -> Result<World, lf_eval::EvalError> {
    if allow_dev {
        World::open_allow_dev(Path::new(dar))
    } else {
        World::open(Path::new(dar))
    }
}

/// `lf-eval [--allow-dev] --batch <dar> <module> <cases.tsv>`: evaluate many cases against one loaded DAR.
///
/// Each non-empty line of the cases file is `id<TAB>def<TAB>arg<TAB>arg...` with the same argument
/// syntax as the single-case form. The result is one line per case on stdout:
/// `id<TAB>OK<TAB>rendered` or `id<TAB>ERR<TAB>message`. Loading the DAR once keeps a few thousand
/// differential cases fast; the exit code is 0 whenever the batch itself ran.
fn run_batch(dar: &str, module: &str, cases: &str, allow_dev: bool) -> ExitCode {
    let world = match open_world(dar, allow_dev) {
        Ok(world) => world,
        Err(err) => {
            eprintln!("Error: {err}");
            return ExitCode::from(1);
        }
    };
    let text = match std::fs::read_to_string(cases) {
        Ok(text) => text,
        Err(err) => {
            eprintln!("Error: cannot read {cases}: {err}");
            return ExitCode::from(1);
        }
    };
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let mut cols = line.split('\t');
        let (Some(id), Some(def)) = (cols.next(), cols.next()) else {
            eprintln!("Error: malformed case line: {line}");
            return ExitCode::from(1);
        };
        let outcome = cols
            .map(parse_arg)
            .collect::<Result<Vec<_>, _>>()
            .and_then(|values| world.eval(module, def, &values))
            .and_then(|value| render(&value));
        match outcome {
            Ok(rendered) => println!("{id}\tOK\t{rendered}"),
            Err(err) => println!("{id}\tERR\t{}", err.to_string().replace(['\t', '\n'], " ")),
        }
    }
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let mut raw: Vec<String> = Vec::new();
    let mut allow_dev = false;
    for arg in env::args().skip(1) {
        if arg == "--allow-dev" {
            allow_dev = true;
        } else {
            raw.push(arg);
        }
    }
    if raw.first().map(String::as_str) == Some("--batch") {
        let (Some(dar), Some(module), Some(cases)) = (raw.get(1), raw.get(2), raw.get(3)) else {
            eprintln!("usage: lf-eval [--allow-dev] --batch <dar> <module> <cases.tsv>");
            return ExitCode::from(2);
        };
        return run_batch(dar, module, cases, allow_dev);
    }
    let mut args = raw.into_iter();
    let Some(dar) = args.next() else {
        eprintln!("usage: lf-eval [--allow-dev] <dar> <module> <def> <arg>...");
        return ExitCode::from(2);
    };
    let Some(module) = args.next() else {
        eprintln!("usage: lf-eval [--allow-dev] <dar> <module> <def> <arg>...");
        return ExitCode::from(2);
    };
    let Some(def) = args.next() else {
        eprintln!("usage: lf-eval [--allow-dev] <dar> <module> <def> <arg>...");
        return ExitCode::from(2);
    };
    let world = match open_world(&dar, allow_dev) {
        Ok(world) => world,
        Err(err) => {
            eprintln!("Error: {err}");
            return ExitCode::from(1);
        }
    };
    let mut values = Vec::new();
    for arg in args {
        match parse_arg(&arg) {
            Ok(value) => values.push(value),
            Err(err) => {
                eprintln!("Error: {err}");
                return ExitCode::from(1);
            }
        }
    }
    match world.eval(&module, &def, &values) {
        Ok(value) => match render(&value) {
            Ok(text) => {
                println!("{text}");
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("Error: {err}");
                ExitCode::from(1)
            }
        },
        Err(err) => {
            eprintln!("Error: {err}");
            ExitCode::from(1)
        }
    }
}
