//! What the executable can measure about itself: the shared libraries it links (G11).
//!
//! [CANTON-NOTE: SEMANTICS] A library is a **system** library when the operating system ships it: on macOS the files under `/usr/lib/` and
//! `/System/Library/`, on Linux the C runtime (`libc`, `libm`, `libgcc_s`, `libpthread`, `libdl`, `librt`, `libutil`, the dynamic loader and
//! the vDSO). Anything else, a JVM library in particular, is foreign. The check reads what the platform's own tool (`otool -L`, `ldd`)
//! prints; a tool that cannot be run is an error, never a pass.
use std::path::Path;
use std::process::Command;

#[derive(Debug, PartialEq, Eq)]
pub struct Report {
    pub libraries: Vec<String>,
    pub foreign: Vec<String>,
    pub jvm_processes: usize,
}

/// The libraries named by the output of `otool -L` (the first line, the binary itself, is skipped) or of `ldd`.
pub fn parse_linked(output: &str, macos: bool) -> Vec<String> {
    output
        .lines()
        .skip(usize::from(macos))
        .filter_map(|line| {
            let line = line.trim();
            if macos {
                line.split(" (").next().map(str::to_string)
            } else {
                // `libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x...)`, `linux-vdso.so.1 (0x...)`, `/lib64/ld-linux-x86-64.so.2 (0x...)`
                let name = line.split(" =>").next()?.split(" (").next()?.trim();
                (!name.is_empty()).then(|| name.to_string())
            }
        })
        .collect()
}

/// Whether the operating system ships the library.
pub fn is_system(lib: &str, macos: bool) -> bool {
    if macos {
        return lib.starts_with("/usr/lib/") || lib.starts_with("/System/Library/");
    }
    let base = lib.rsplit('/').next().unwrap_or(lib);
    const SYSTEM: [&str; 9] = [
        "libc.so",
        "libm.so",
        "libgcc_s.so",
        "libpthread.so",
        "libdl.so",
        "librt.so",
        "libutil.so",
        "ld-linux",
        "linux-vdso",
    ];
    SYSTEM.iter().any(|s| base.starts_with(s)) || base == "ld.so.1"
}

pub fn audit_binary(exe: &Path) -> Result<Report, String> {
    let macos = cfg!(target_os = "macos");
    let output = if macos {
        Command::new("otool").arg("-L").arg(exe).output()
    } else {
        Command::new("ldd").arg(exe).output()
    }
    .map_err(|e| format!("cannot list the libraries of {}: {e}", exe.display()))?;
    if !output.status.success() {
        return Err(format!(
            "listing the libraries of {} failed: {}",
            exe.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let libraries = parse_linked(&String::from_utf8_lossy(&output.stdout), macos);
    if libraries.is_empty() {
        return Err(format!("the library listing of {} is empty", exe.display()));
    }
    let foreign = libraries
        .iter()
        .filter(|l| !is_system(l, macos))
        .cloned()
        .collect();
    let jvm_processes = Command::new("ps")
        .args(["-A", "-o", "comm"])
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|l| {
                    let base = l
                        .trim()
                        .rsplit('/')
                        .next()
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    matches!(base.as_str(), "java" | "javaw" | "scala")
                })
                .count()
        })
        .unwrap_or(0);
    Ok(Report {
        libraries,
        foreign,
        jvm_processes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const OTOOL: &str = "/x/canton-rs:\n\t/usr/lib/libiconv.2.dylib (compatibility version 7.0.0, current version 7.0.0)\n\t/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation (compatibility version 150.0.0)\n\t/opt/homebrew/lib/libjvm.dylib (compatibility version 1.0.0)\n";
    const LDD: &str = "\tlinux-vdso.so.1 (0x00007ffc)\n\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f)\n\tlibjvm.so => /opt/jdk/lib/server/libjvm.so (0x00007e)\n\t/lib64/ld-linux-x86-64.so.2 (0x00007d)\n";

    #[test]
    fn libraries_are_read_and_a_foreign_one_is_found() {
        let mac = parse_linked(OTOOL, true);
        assert_eq!(mac.len(), 3);
        let foreign: Vec<_> = mac.iter().filter(|l| !is_system(l, true)).collect();
        assert_eq!(foreign, ["/opt/homebrew/lib/libjvm.dylib"]);
        let linux = parse_linked(LDD, false);
        assert_eq!(linux.len(), 4, "{linux:?}");
        let foreign: Vec<_> = linux.iter().filter(|l| !is_system(l, false)).collect();
        assert_eq!(foreign, ["libjvm.so"]);
    }

    #[test]
    fn a_library_that_is_not_the_systems_is_foreign_even_when_it_is_no_jvm() {
        assert!(!is_system("/usr/local/lib/libssl.3.dylib", true));
        assert!(!is_system("libssl.so.3", false));
        assert!(is_system("/usr/lib/libSystem.B.dylib", true));
        assert!(is_system("libc.so.6", false));
    }

    #[test]
    fn this_test_binary_links_only_system_libraries() {
        let exe = std::env::current_exe().unwrap();
        let report = audit_binary(&exe).unwrap();
        assert!(report.foreign.is_empty(), "{:?}", report.foreign);
        assert!(!report.libraries.is_empty());
    }
}
