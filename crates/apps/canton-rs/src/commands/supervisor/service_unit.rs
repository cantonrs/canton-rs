//! OS boot service unit generator (`systemd` `.service` / `launchd` `.plist`) for `daemon install-service`.
//!
//! [CANTON-NOTE: WHY] The init system restarts the supervisor (`Restart=always` / `KeepAlive`) and the supervisor restarts its nodes.
//! The supervisor does not exit when a node fails, so a unit with `--no-restart` left a crashed node down for good.

use std::path::{Path, PathBuf};

/// Target init/service format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceFormat {
    Systemd,
    Launchd,
}

impl ServiceFormat {
    /// Returns host platform default service format.
    pub fn host_default() -> Self {
        if cfg!(target_os = "macos") {
            Self::Launchd
        } else {
            Self::Systemd
        }
    }
}

/// Parameters controlling generated unit file paths and activation.
#[derive(Clone, Debug)]
pub struct InstallServiceOptions {
    pub service_name: String,
    pub state_dir: PathBuf,
    pub workdir: PathBuf,
    pub exe_path: PathBuf,
    pub daemon_args: Vec<String>,
    pub system_wide: bool,
    pub format: ServiceFormat,
    pub output_path: Option<PathBuf>,
    pub apply: bool,
}

/// Renders a Linux `systemd` unit file with `KillMode=control-group`.
pub fn render_systemd_unit(opts: &InstallServiceOptions) -> String {
    let mut exec_args = vec![
        shell_quote(&opts.exe_path.display().to_string()),
        "daemon".to_string(),
        "up".to_string(),
    ];
    exec_args.extend(opts.daemon_args.iter().map(|a| shell_quote(a)));
    let exec_start = exec_args.join(" ");
    let wanted_by = if opts.system_wide {
        "multi-user.target"
    } else {
        "default.target"
    };
    format!(
        "[Unit]\n\
         Description=canton-rs Supervisor Daemon ({name})\n\
         After=network-online.target\n\n\
         [Service]\n\
         Type=simple\n\
         WorkingDirectory={workdir}\n\
         ExecStart={exec_start}\n\
         Restart=always\n\
         RestartSec=3\n\
         KillMode=control-group\n\
         TimeoutStopSec=15\n\
         LimitNOFILE=65536\n\n\
         [Install]\n\
         WantedBy={wanted_by}\n",
        name = single_line(&opts.service_name).replace('%', "%%"),
        workdir = single_line(&opts.workdir.display().to_string()),
    )
}

/// Renders a macOS `launchd` `.plist` logging to `<state-dir>/logs/supervisor.log`.
pub fn render_launchd_plist(opts: &InstallServiceOptions) -> String {
    let label = format!("io.canton-rs.{}", sanitize_label(&opts.service_name));
    let log_path = opts.state_dir.join("logs").join("supervisor.log");
    let mut program_args = vec![
        opts.exe_path.display().to_string(),
        "daemon".to_string(),
        "up".to_string(),
    ];
    program_args.extend(opts.daemon_args.iter().cloned());
    let arg_xml: String = program_args
        .into_iter()
        .map(|a| format!("        <string>{}</string>\n", xml_escape(&a)))
        .collect();
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
             <key>Label</key>\n\
             <string>{}</string>\n\
             <key>WorkingDirectory</key>\n\
             <string>{}</string>\n\
             <key>ProgramArguments</key>\n\
             <array>\n\
         {arg_xml}\
             </array>\n\
             <key>RunAtLoad</key>\n\
             <true/>\n\
             <key>KeepAlive</key>\n\
             <true/>\n\
             <key>StandardOutPath</key>\n\
             <string>{}</string>\n\
             <key>StandardErrorPath</key>\n\
             <string>{}</string>\n\
         </dict>\n\
         </plist>\n",
        xml_escape(&label),
        xml_escape(&opts.workdir.display().to_string()),
        xml_escape(&log_path.display().to_string()),
        xml_escape(&log_path.display().to_string()),
    )
}

/// Writes the OS service definition file and returns `(written_path, activation_hint)`.
pub fn install_service_file(opts: &InstallServiceOptions) -> Result<(PathBuf, String), String> {
    let target = match &opts.output_path {
        Some(p) => p.clone(),
        None => default_unit_path(opts)?,
    };
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create parent dir {}: {e}", parent.display()))?;
    }
    let body = match opts.format {
        ServiceFormat::Systemd => render_systemd_unit(opts),
        ServiceFormat::Launchd => render_launchd_plist(opts),
    };
    std::fs::write(&target, body)
        .map_err(|e| format!("cannot write service definition {}: {e}", target.display()))?;
    if opts.format == ServiceFormat::Launchd {
        let logs = opts.state_dir.join("logs");
        std::fs::create_dir_all(&logs)
            .map_err(|e| format!("cannot create log dir {}: {e}", logs.display()))?;
    }

    let mut hint = match opts.format {
        ServiceFormat::Systemd => {
            if opts.system_wide {
                format!(
                    "sudo systemctl daemon-reload && sudo systemctl enable --now {}",
                    target
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("canton-rs-daemon.service")
                )
            } else {
                format!(
                    "systemctl --user daemon-reload && systemctl --user enable --now {}",
                    target
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("canton-rs-daemon.service")
                )
            }
        }
        ServiceFormat::Launchd => format!("launchctl load -w {}", target.display()),
    };

    if opts.apply && opts.format == ServiceFormat::Systemd {
        if let Some(wants_link) = systemd_wants_symlink(&target, opts.system_wide) {
            if let Some(parent) = wants_link.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            #[cfg(unix)]
            let _ = std::os::unix::fs::symlink(&target, &wants_link);
            hint = format!("{hint} (symlinked {})", wants_link.display());
        }
    }

    Ok((target, hint))
}

fn default_unit_path(opts: &InstallServiceOptions) -> Result<PathBuf, String> {
    let home = std::env::var("HOME")
        .map(PathBuf::from)
        .map_err(|_| "HOME environment variable is not set; pass --output <path>".to_string())?;
    let name = sanitize_label(&opts.service_name);
    Ok(match opts.format {
        ServiceFormat::Systemd => {
            if opts.system_wide {
                PathBuf::from(format!("/etc/systemd/system/canton-rs-{name}.service"))
            } else {
                home.join(".config/systemd/user")
                    .join(format!("canton-rs-{name}.service"))
            }
        }
        ServiceFormat::Launchd => {
            let base = if opts.system_wide {
                PathBuf::from("/Library/LaunchDaemons")
            } else {
                home.join("Library/LaunchAgents")
            };
            base.join(format!("io.canton-rs.{name}.plist"))
        }
    })
}

fn systemd_wants_symlink(unit: &Path, system_wide: bool) -> Option<PathBuf> {
    let fname = unit.file_name()?;
    let target_dir = if system_wide {
        PathBuf::from("/etc/systemd/system/multi-user.target.wants")
    } else {
        let home = std::env::var_os("HOME")?;
        PathBuf::from(home).join(".config/systemd/user/default.target.wants")
    };
    Some(target_dir.join(fname))
}

fn sanitize_label(raw: &str) -> String {
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_') {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// Quotes one `ExecStart` word for systemd, which expands `%` specifiers and `$` variables even inside double quotes.
fn shell_quote(s: &str) -> String {
    let s = single_line(s).replace('%', "%%").replace('$', "$$");
    if !s.contains([' ', '\t', '"', '\'', '\\']) {
        return s;
    }
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// A newline in a unit value would end the directive and start another.
fn single_line(s: &str) -> String {
    s.replace(['\n', '\r'], " ")
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(name: &str, args: &[&str]) -> InstallServiceOptions {
        InstallServiceOptions {
            service_name: name.into(),
            state_dir: PathBuf::from("/tmp/canton-state"),
            workdir: PathBuf::from("/work/app"),
            exe_path: PathBuf::from("/usr/local/bin/canton-rs"),
            daemon_args: args.iter().map(|a| a.to_string()).collect(),
            system_wide: false,
            format: ServiceFormat::Systemd,
            output_path: None,
            apply: false,
        }
    }

    /// The supervisor in a unit restarts failed nodes itself (the init system restarts the supervisor), so the unit does not pass
    /// `--no-restart`: with it a crashed node stayed down while the supervisor kept running.
    #[test]
    fn units_keep_the_supervisor_restarting_its_nodes() {
        let opts = opts("local-dev", &["-f", "canton-daemon.yaml"]);
        let systemd = render_systemd_unit(&opts);
        assert!(!systemd.contains("--no-restart"), "{systemd}");
        assert!(systemd.contains("KillMode=control-group"));
        assert!(systemd.contains("Restart=always"));

        let launchd = render_launchd_plist(&opts);
        assert!(!launchd.contains("--no-restart"), "{launchd}");
        assert!(launchd.contains("io.canton-rs.local-dev"));
        assert!(launchd.contains("<key>KeepAlive</key>"));
    }

    /// systemd expands `%` specifiers and `$` variables even inside quotes, and a newline in Description would start a new directive.
    #[test]
    fn systemd_unit_escapes_specifiers_variables_and_newlines() {
        let opts = opts(
            "dev\nExecStartPre=/bin/false",
            &["-f", "$HOME/50% stack.yaml"],
        );
        let unit = render_systemd_unit(&opts);
        assert!(!unit.contains("\nExecStartPre"), "{unit}");
        assert!(unit.contains("\"$$HOME/50%% stack.yaml\""), "{unit}");
    }

    /// `install-service` for launchd creates the log directory the plist points at (launchd does not).
    #[test]
    fn launchd_install_creates_the_log_directory() {
        let root = std::env::temp_dir().join(format!("canton-unit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let mut o = opts("dev", &[]);
        o.format = ServiceFormat::Launchd;
        o.state_dir = root.join("state");
        o.output_path = Some(root.join("io.canton-rs.dev.plist"));
        install_service_file(&o).expect("install");
        assert!(root.join("state/logs").is_dir());
        let _ = std::fs::remove_dir_all(&root);
    }
}
