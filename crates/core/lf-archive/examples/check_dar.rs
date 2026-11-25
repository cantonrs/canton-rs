//! Prints, for each DAR given, whether it loads and whether its packages type-check (a tool for U-11), and which `DarError`
//! variant refuses it (a tool for mapping the errors to the node's upload codes, S-LF-014).
use lf_archive::{check_dar_for_upload, parse_loaded_dar};
fn main() {
    for path in std::env::args().skip(1) {
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                println!("{path}: unreadable {e}");
                continue;
            }
        };
        match parse_loaded_dar(std::io::Cursor::new(bytes)) {
            Err(e) => println!(
                "{path}: LOAD-ERR {}",
                format!("{e:?}").chars().take(60).collect::<String>()
            ),
            Ok(l) => match check_dar_for_upload(&l, &Default::default()) {
                Ok(()) => println!("{path}: ok ({} packages)", l.packages.len()),
                Err(e) => println!(
                    "{path}: UPLOAD-ERR {}",
                    format!("{e:?}").chars().take(60).collect::<String>()
                ),
            },
        }
    }
}
