use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let Some(name) = env::args().nth(1) else {
        eprintln!("usage: tx-ledger <case>");
        return ExitCode::from(2);
    };
    match lf_eval::ledger::run_case(&name) {
        Ok(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}
