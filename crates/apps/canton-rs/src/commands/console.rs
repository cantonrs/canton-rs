//! The Canton console (`canton-rs console`) (G10 F2, AT-K07, S-TOOLS-001).
//!
//! Runs console statements the way the Canton 3.7.2 console runs a `.canton` script, against participants reached over their JSON
//! Ledger API (`--participant participant1=localhost:7575`):
//!
//! ```text
//! val pkg = participant1.dars.upload("model.dar")
//! val alice = participant1.ledger_api.parties.allocate("alice").party
//! println(participant1.ledger_api.parties.list().size)
//! ```
//!
//! A statement is `val name = expr`, `println(expr)` or `expr`. An expression is a literal (`"text"`, `42`, `true`), a variable, or a node
//! followed by a console command path and its call (`participant1.ledger_api.state.end()`), then any of the collection and field steps
//! [`Value::step`] serves (`.size`, `.map(_.party)`, `.sorted`, `.mkString(",")`, `.contains(x)`, a field such as `.party`).
//!
//! [CANTON-NOTE: SEMANTICS] The command surface is the official one: every command path is checked against the 3.7.2 console inventory
//! (`tests/oracle/provenance/g0-3.7.2-console/console-dsl-inventory.tsv`, collected from the node's own `Help`, 685 commands). A path that
//! is in the inventory and not served here is refused as such; a path that is not in it is refused as no console command.
//!
//! [CANTON-NOTE: WHY] This command used to print fixed text for a handful of names (`health.status` said every node was ONLINE without
//! asking any). It now asks the node, or says it cannot.
//!
//! [CANTON-NOTE: LIMITATION] Only participant commands, and only those [`serve`] lists; no Scala beyond the statements above.
use std::collections::BTreeMap;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};
use serde_json::{json, Value as Json};

use super::json_http::{call, call_json, error_cause};
use super::supervisor::cli::DEFAULT_STATE_DIR;
use super::supervisor::ipc::{call_unary, IpcRequest, IpcResponse};
use super::supervisor::{NodeLifecycleState, NodeRole};

mod parser;

pub use parser::Value;

use parser::{tokenize, CallArgs, Expr, Parser, Step, Token};

#[derive(Subcommand, Debug, Clone)]
pub enum ConsoleAction {
    /// Zero-Config attach to a running `canton-rs daemon` cluster via `daemon.sock`.
    Attach(AttachArgs),
    /// Execute a Canton 3.7.2 console statement against a running `canton-rs daemon` cluster.
    Exec(ExecArgs),
}

#[derive(Args, Debug, Clone)]
pub struct AttachArgs {
    /// Supervisor state directory containing `daemon.sock`.
    #[arg(long, default_value = DEFAULT_STATE_DIR)]
    pub state_dir: PathBuf,
}

#[derive(Args, Debug, Clone)]
pub struct ExecArgs {
    /// Console statement or `;`-separated statements to run (`participants`, `participant1.stop()`, etc.).
    pub statement: String,
    /// Supervisor state directory containing `daemon.sock`.
    #[arg(long, default_value = DEFAULT_STATE_DIR)]
    pub state_dir: PathBuf,
}

#[derive(Args, Debug)]
pub struct ConsoleArgs {
    #[command(subcommand)]
    pub action: Option<ConsoleAction>,

    /// A participant the statements can name: `name=host:port` of its JSON Ledger API (repeat for several).
    #[arg(long = "participant", value_name = "NAME=HOST:PORT")]
    pub participants: Vec<String>,

    /// Run the statements of this `.canton` file.
    #[arg(short, long)]
    pub script: Option<String>,

    /// Run these statements (one per line, or separated by `;`).
    #[arg(short, long)]
    pub eval: Option<String>,

    /// Read statements from the terminal.
    #[arg(short, long, default_value_t = false)]
    pub interactive: bool,
}

const INVENTORY: &str = include_str!(
    "../../../../../tests/oracle/provenance/g0-3.7.2-console/console-dsl-inventory.tsv"
);

/// The command paths of a scope (`participant`, `sequencer`, `mediator`, `top_level`) in the 3.7.2 console.
fn inventory_has(scope: &str, path: &str) -> bool {
    INVENTORY.lines().skip(1).any(|l| {
        let mut cols = l.split('\t');
        cols.next() == Some(scope) && cols.next() == Some(path)
    })
}

pub fn execute_console(args: ConsoleArgs) -> Result<(), String> {
    if let Some(action) = args.action {
        return match action {
            ConsoleAction::Attach(a) => execute_attach(a),
            ConsoleAction::Exec(e) => execute_exec(e),
        };
    }
    let mut console = Console::new(&args.participants)?;
    if let Some(path) = &args.script {
        let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
        return console.run(&text);
    }
    if let Some(text) = &args.eval {
        return console.run(&text.replace(';', "\n"));
    }
    if args.interactive && io::stdin().is_terminal() {
        return run_repl(&mut console, false);
    }
    Err("give statements to run: --script <file>, --eval <statements> or --interactive".into())
}

/// Attaches an interactive `@ ` console session to a running `canton-rs daemon` cluster.
pub fn execute_attach(args: AttachArgs) -> Result<(), String> {
    let mut console = Console::from_supervisor(&args.state_dir)?;
    let bound_names: Vec<String> = console.nodes.keys().cloned().collect();
    let stack = console
        .supervisor_stack
        .as_deref()
        .unwrap_or("canton-daemon");
    println!(
        "Attached to canton-rs daemon ({stack}: {})",
        bound_names.join(", ")
    );
    run_repl(&mut console, true)
}

/// Executes one or more semicolon-separated Canton 3.7.2 console statements against `daemon.sock`.
pub fn execute_exec(args: ExecArgs) -> Result<(), String> {
    let mut console = Console::from_supervisor(&args.state_dir)?;
    for raw in args.statement.replace(';', "\n").lines() {
        let line = strip_comment(raw).trim();
        if line.is_empty() || line.starts_with("import ") || line == "exit" {
            continue;
        }
        if line == "help" {
            println!("Available Canton 3.7.2 scopes: participants, sequencers, mediators, nodes, health.status(), <node>.stop(), <node>.start(), <node>.health.is_running()");
            continue;
        }
        if let Some(rendered) = console.statement_output(line)? {
            println!("{rendered}");
        }
    }
    Ok(())
}

fn run_repl(console: &mut Console, print_values: bool) -> Result<(), String> {
    let stdin = io::stdin();
    let interactive_tty = stdin.is_terminal();
    loop {
        if interactive_tty {
            print!("@ ");
            io::stdout().flush().map_err(|e| e.to_string())?;
        }
        let mut line = String::new();
        if stdin
            .lock()
            .read_line(&mut line)
            .map_err(|e| e.to_string())?
            == 0
        {
            break;
        }
        let line = strip_comment(&line).trim();
        if line.is_empty() || line.starts_with("import ") {
            continue;
        }
        if line == "exit" {
            break;
        }
        if line == "help" {
            println!("Available scopes: participants, sequencers, mediators, nodes, health.status(), <node>.stop(), <node>.start(), <node>.health.is_running(), <node>.ledger_api.*, <node>.dars.*");
            continue;
        }
        let res = if print_values {
            console.statement_output(line).map(|opt| {
                if let Some(s) = opt {
                    println!("{s}");
                }
            })
        } else {
            console.run(line)
        };
        if let Err(e) = res {
            if interactive_tty {
                println!("ERROR: {e}");
            } else {
                return Err(e);
            }
        }
    }
    Ok(())
}

/// Kind of node bound in the Canton console.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BoundRole {
    Participant,
    Sequencer,
    Mediator,
}

impl BoundRole {
    const fn scope(self) -> &'static str {
        match self {
            Self::Participant => "participant",
            Self::Sequencer => "sequencer",
            Self::Mediator => "mediator",
        }
    }
}

/// A Canton node the console reaches (standalone participant HTTP or supervisor slot).
#[derive(Clone, Debug)]
struct Node {
    role: BoundRole,
    host: String,
    port: u16,
    stopped: bool,
    status_label: String,
}

pub struct Console {
    nodes: BTreeMap<String, Node>,
    vars: BTreeMap<String, Value>,
    supervisor_state_dir: Option<PathBuf>,
    supervisor_stack: Option<String>,
}

impl Console {
    fn new(participants: &[String]) -> Result<Self, String> {
        let mut nodes = BTreeMap::new();
        for p in participants {
            let (name, address) = p
                .split_once('=')
                .ok_or_else(|| format!("--participant {p}: expected name=host:port"))?;
            let (host, port) = address
                .rsplit_once(':')
                .ok_or_else(|| format!("--participant {p}: expected name=host:port"))?;
            let port = port
                .parse()
                .map_err(|_| format!("--participant {p}: bad port"))?;
            nodes.insert(
                name.to_string(),
                Node {
                    role: BoundRole::Participant,
                    host: host.to_string(),
                    port,
                    stopped: false,
                    status_label: "Running".to_string(),
                },
            );
        }
        Ok(Self {
            nodes,
            vars: BTreeMap::new(),
            supervisor_state_dir: None,
            supervisor_stack: None,
        })
    }

    fn from_supervisor(state_dir: &Path) -> Result<Self, String> {
        let mut console = Self {
            nodes: BTreeMap::new(),
            vars: BTreeMap::new(),
            supervisor_state_dir: Some(state_dir.to_path_buf()),
            supervisor_stack: None,
        };
        console.refresh_from_supervisor()?;
        Ok(console)
    }

    fn refresh_from_supervisor(&mut self) -> Result<(), String> {
        let Some(dir) = &self.supervisor_state_dir else {
            return Ok(());
        };
        let IpcResponse::Snapshot { snapshot, .. } = call_unary(dir, &IpcRequest::GetSnapshot)?
        else {
            return Err("unexpected supervisor IPC response".to_string());
        };
        self.supervisor_stack = Some(snapshot.stack_name);
        self.nodes.clear();
        for node in snapshot.nodes {
            let (role, port) = match node.role {
                NodeRole::Participant => (
                    BoundRole::Participant,
                    node.ports.http_json.or(node.ports.grpc_ledger).unwrap_or(0),
                ),
                NodeRole::Sequencer => (
                    BoundRole::Sequencer,
                    node.ports
                        .metrics
                        .or(node.ports.admin)
                        .or(node.ports.public)
                        .unwrap_or(0),
                ),
                NodeRole::Mediator => (
                    BoundRole::Mediator,
                    node.ports.admin.or(node.ports.http_json).unwrap_or(0),
                ),
                NodeRole::Splice | NodeRole::Scan | NodeRole::Pqs => continue,
            };
            self.nodes.insert(
                node.name,
                Node {
                    role,
                    host: "127.0.0.1".to_string(),
                    port,
                    stopped: matches!(
                        node.state,
                        NodeLifecycleState::Stopped | NodeLifecycleState::Failed
                    ),
                    status_label: node.state.display_label().to_string(),
                },
            );
        }
        Ok(())
    }

    /// Runs statements, one per line; stops at the first that fails.
    pub fn run(&mut self, text: &str) -> Result<(), String> {
        for (n, line) in text.lines().enumerate() {
            let line = strip_comment(line).trim();
            if line.is_empty() || line.starts_with("import ") {
                continue;
            }
            self.statement(line)
                .map_err(|e| format!("line {}: {e}", n + 1))?;
        }
        Ok(())
    }

    fn statement_output(&mut self, line: &str) -> Result<Option<String>, String> {
        let tokens = tokenize(line)?;
        let mut p = Parser { tokens, at: 0 };
        if p.eat_ident("val") {
            let name = p.ident()?;
            p.expect(&Token::Sym('='))?;
            let expr = p.expr()?;
            p.end()?;
            let value = self.eval(&expr)?;
            self.vars.insert(name, value);
            Ok(None)
        } else if p.peek() == Some(&Token::Ident("println".into())) {
            p.at += 1;
            p.expect(&Token::Sym('('))?;
            let expr = p.expr()?;
            p.expect(&Token::Sym(')'))?;
            p.end()?;
            Ok(Some(self.eval(&expr)?.show()))
        } else {
            let expr = p.expr()?;
            p.end()?;
            let value = self.eval(&expr)?;
            if matches!(value, Value::Unit) {
                Ok(None)
            } else {
                Ok(Some(value.show()))
            }
        }
    }

    fn statement(&mut self, line: &str) -> Result<(), String> {
        let tokens = tokenize(line)?;
        let mut p = Parser { tokens, at: 0 };
        if p.eat_ident("val") {
            let name = p.ident()?;
            p.expect(&Token::Sym('='))?;
            let expr = p.expr()?;
            p.end()?;
            let value = self.eval(&expr)?;
            self.vars.insert(name, value);
        } else if p.peek() == Some(&Token::Ident("println".into())) {
            p.at += 1;
            p.expect(&Token::Sym('('))?;
            let expr = p.expr()?;
            p.expect(&Token::Sym(')'))?;
            p.end()?;
            println!("{}", self.eval(&expr)?.show());
        } else {
            let expr = p.expr()?;
            p.end()?;
            self.eval(&expr)?;
        }
        Ok(())
    }

    fn eval(&mut self, expr: &Expr) -> Result<Value, String> {
        match expr {
            Expr::Lit(v) => Ok(v.clone()),
            Expr::Collection(kind, items) => {
                let items = items
                    .iter()
                    .map(|i| self.eval(i))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(match (kind.as_str(), items.len()) {
                    // `Map(k -> v, ...)`: the parser gives the keys and values in turn
                    ("Map", _) => {
                        let mut fields = BTreeMap::new();
                        for pair in items.chunks(2) {
                            let [Value::Text(k), v] = pair else {
                                return Err("a Map's keys are texts here".into());
                            };
                            fields.insert(k.clone(), v.clone());
                        }
                        Value::Object(fields)
                    }
                    ("Some", 1) => Value::Some(Box::new(items.into_iter().next().expect("one"))),
                    ("Some", n) => return Err(format!("Some takes one value, not {n}")),
                    _ => Value::Seq(items),
                })
            }
            Expr::Lambda(_) => Err("a function is only an argument of map".into()),
            Expr::Path { root, steps } => {
                // `node.a.b.c(args)` is one command; what follows it is steps on its value
                let (mut value, rest) = if let Some(v) = self.vars.get(root) {
                    (v.clone(), &steps[..])
                } else if let Some(bound) = self.nodes.get(root).cloned() {
                    let (path, args, call_at) = self.call(root, steps)?;
                    let val = self.serve_bound_node(root, &bound, &path, &args)?;
                    (val, &steps[call_at + 1..])
                } else if root == "ledger_api_utils" {
                    // a top-level object of the console: the whole path is one command of the `top_level` scope
                    let (path, args, call_at) = self.call(root, steps)?;
                    (
                        serve_top_level(&format!("{root}.{path}"), &args)?,
                        &steps[call_at + 1..],
                    )
                } else if matches!(
                    root.as_str(),
                    "participants" | "sequencers" | "mediators" | "nodes"
                ) && inventory_has("top_level", root)
                {
                    self.refresh_from_supervisor()?;
                    let val = self.top_level_node_list(root);
                    (val, &steps[..])
                } else if root == "health" {
                    let (path, _args, call_at) = self.call(root, steps)?;
                    let full = format!("health.{path}");
                    if !inventory_has("top_level", &full) {
                        return Err(format!("{full} is not a Canton 3.7.2 console command"));
                    }
                    if full == "health.status" {
                        self.refresh_from_supervisor()?;
                        let mut summary = BTreeMap::new();
                        for (name, n) in &self.nodes {
                            summary.insert(name.clone(), Value::Text(n.status_label.clone()));
                        }
                        (Value::Object(summary), &steps[call_at + 1..])
                    } else {
                        return Err(format!(
                            "{full} is a Canton 3.7.2 console command this console does not serve"
                        ));
                    }
                } else {
                    return Err(format!("not found: value {root}"));
                };
                for step in rest {
                    let args = match &step.args {
                        Some(args) => args
                            .iter()
                            .map(|a| match &a.expr {
                                Expr::Lambda(field) => Ok(Value::Lambda(field.clone())),
                                other => self.eval(other),
                            })
                            .collect::<Result<Vec<_>, _>>()?,
                        None => Vec::new(),
                    };
                    value = value.step(&step.name, &args)?;
                }
                Ok(value)
            }
        }
    }
}

impl Console {
    /// The command a path calls: its path up to the call, the arguments, and the index of the calling step. Scala calls a method
    /// without parameters with or without `()` (`participant1.id`).
    fn call(&mut self, root: &str, steps: &[Step]) -> Result<(String, CallArgs, usize), String> {
        let call_at = steps
            .iter()
            .position(|s| s.args.is_some())
            .or_else(|| steps.len().checked_sub(1))
            .ok_or_else(|| format!("{root} is not a command"))?;
        let mut args = CallArgs::default();
        for arg in steps[call_at].args.iter().flatten() {
            let value = self.eval(&arg.expr)?;
            match &arg.name {
                Some(name) => {
                    args.named.insert(name.clone(), value);
                }
                None => args.positional.push(value),
            }
        }
        Ok((names(&steps[..=call_at]), args, call_at))
    }

    fn top_level_node_list(&self, root: &str) -> Value {
        let items = self
            .nodes
            .iter()
            .filter(|(_, n)| match root {
                "participants" => n.role == BoundRole::Participant,
                "sequencers" => n.role == BoundRole::Sequencer,
                "mediators" => n.role == BoundRole::Mediator,
                _ => true,
            })
            .map(|(name, _)| Value::Text(name.clone()))
            .collect();
        Value::Seq(items)
    }

    fn serve_bound_node(
        &mut self,
        node: &str,
        bound: &Node,
        path: &str,
        args: &CallArgs,
    ) -> Result<Value, String> {
        let scope = bound.role.scope();
        if !inventory_has(scope, path) {
            return Err(format!(
                "{node}.{path} is not a Canton 3.7.2 console command"
            ));
        }

        if path == "stop" {
            let dir = self.supervisor_state_dir.clone().ok_or_else(|| {
                format!(
                    "{node}.stop() requires an attached supervisor ('canton-rs console attach')"
                )
            })?;
            call_unary(
                &dir,
                &IpcRequest::StopNodes {
                    targets: vec![node.to_string()],
                },
            )?;
            self.refresh_from_supervisor()?;
            return Ok(Value::Unit);
        }
        if path == "start" {
            let dir = self.supervisor_state_dir.clone().ok_or_else(|| {
                format!(
                    "{node}.start() requires an attached supervisor ('canton-rs console attach')"
                )
            })?;
            call_unary(
                &dir,
                &IpcRequest::StartNodes {
                    targets: vec![node.to_string()],
                },
            )?;
            self.refresh_from_supervisor()?;
            return Ok(Value::Unit);
        }

        if path == "health.is_running" {
            if self.supervisor_state_dir.is_some() {
                self.refresh_from_supervisor()?;
                let live = self.nodes.get(node).is_some_and(|n| !n.stopped);
                return Ok(Value::Bool(live));
            }
            return serve(&bound.host, bound.port, node, path, args);
        }

        if path == "health.status" {
            if self.supervisor_state_dir.is_some() {
                self.refresh_from_supervisor()?;
                let st = self
                    .nodes
                    .get(node)
                    .map_or_else(|| "Unknown".to_string(), |n| n.status_label.clone());
                return Ok(Value::Text(st));
            }
            let (code, _) = call(&bound.host, bound.port, "GET", "/livez", None)?;
            return Ok(Value::Text(if code == 200 {
                "Running".to_string()
            } else {
                format!("HTTP {code}")
            }));
        }

        if bound.stopped {
            return Err(format!(
                "{node} is stopped (start it with '{node}.start()' or 'canton-rs daemon start {node}')"
            ));
        }

        match bound.role {
            BoundRole::Participant => serve(&bound.host, bound.port, node, path, args),
            BoundRole::Sequencer | BoundRole::Mediator => Err(format!(
                "{node}.{path} is a Canton 3.7.2 console command this console does not serve"
            )),
        }
    }
}

/// The top-level commands this console serves: `ledger_api_utils.create(packageId, module, template, arguments)` and
/// `ledger_api_utils.exercise(packageId, module, template, choice, arguments, contractId)` build a Ledger API `Command` (no node is asked).
fn serve_top_level(path: &str, args: &CallArgs) -> Result<Value, String> {
    let text = |i: usize, name: &str| -> Result<String, String> {
        match args.get(i, name) {
            Some(Value::Text(t)) => Ok(t.clone()),
            other => Err(format!("{path}: {name} expected, got {other:?}")),
        }
    };
    let arguments = |i: usize| -> Result<Json, String> {
        match args.get(i, "arguments") {
            Some(v @ Value::Object(_)) => Ok(v.to_json()),
            other => Err(format!("{path}: arguments (a Map) expected, got {other:?}")),
        }
    };
    match path {
        "ledger_api_utils.create" => {
            let template_id = format!(
                "{}:{}:{}",
                text(0, "packageId")?,
                text(1, "module")?,
                text(2, "template")?
            );
            Ok(Value::Command(json!({ "CreateCommand": {
                "templateId": template_id,
                "createArguments": arguments(3)?,
            }})))
        }
        "ledger_api_utils.exercise" => {
            let template_id = format!(
                "{}:{}:{}",
                text(0, "packageId")?,
                text(1, "module")?,
                text(2, "template")?
            );
            Ok(Value::Command(json!({ "ExerciseCommand": {
                "templateId": template_id,
                "contractId": text(5, "contractId")?,
                "choice": text(3, "choice")?,
                "choiceArgument": arguments(4)?,
            }})))
        }
        _ if inventory_has("top_level", path) => Err(format!(
            "{path} is a Canton 3.7.2 console command this console does not serve"
        )),
        _ => Err(format!("{path} is not a Canton 3.7.2 console command")),
    }
}

fn names(steps: &[Step]) -> String {
    steps
        .iter()
        .map(|s| s.name.as_str())
        .collect::<Vec<_>>()
        .join(".")
}

fn strip_comment(line: &str) -> &str {
    let mut in_string = false;
    let bytes = line.as_bytes();
    for i in 0..bytes.len() {
        match bytes[i] {
            b'"' => in_string = !in_string,
            b'/' if !in_string && bytes.get(i + 1) == Some(&b'/') => return &line[..i],
            _ => {}
        }
    }
    line
}

/// The participant commands this console serves, each as the JSON Ledger API calls a client makes for it.
///
/// [CANTON-NOTE: SEMANTICS] The values are the console's: `ledger_api.state.end()` the offset (`Long`), `dars.upload(path)` the DAR's
/// main package id, `ledger_api.parties.allocate(hint)` and `.list()` `PartyDetails` (`party`, `isLocal`), `ledger_api.packages.list()`
/// `PackageDetails` (`packageId`), `ledger_api.users.list()` a `UsersPage` (`users` with `id`, `primaryParty`), `.create`/`.get` a `User`,
/// `.delete` unit, `ledger_api.users.rights.list`/`.grant`/`.revoke` `UserRights` (`actAs`, `readAs`, `participantAdmin`, ...; after a
/// change, the rights as they then are), `ledger_api.identity_provider_config.list()` the configurations, `id` the `ParticipantId`, `health.is_running()` a
/// `Boolean`. Arguments go by position or by parameter name, as the signatures of the inventory name them.
fn serve(host: &str, port: u16, node: &str, path: &str, args: &CallArgs) -> Result<Value, String> {
    // an argument by its position or its parameter name, as Scala takes it
    let text_arg = |i: usize, name: &str| -> Result<String, String> {
        match args.get(i, name) {
            Some(Value::Text(t)) => Ok(t.clone()),
            other => Err(format!("{node}.{path}: {name} expected, got {other:?}")),
        }
    };
    let parties_arg = |i: usize, name: &str| -> Result<Vec<String>, String> {
        match args.get(i, name) {
            None => Ok(Vec::new()),
            Some(Value::Seq(items)) => items
                .iter()
                .map(|v| match v {
                    Value::Party(p) => Ok(p.clone()),
                    other => Err(format!(
                        "{node}.{path}: {name}: a party expected, got {other:?}"
                    )),
                })
                .collect(),
            other => Err(format!(
                "{node}.{path}: {name}: a Set of parties expected, got {other:?}"
            )),
        }
    };
    let bool_arg = |i: usize, name: &str| -> Result<bool, String> {
        match args.get(i, name) {
            None => Ok(false),
            Some(Value::Bool(b)) => Ok(*b),
            other => Err(format!(
                "{node}.{path}: {name}: a Boolean expected, got {other:?}"
            )),
        }
    };
    // [CANTON-NOTE: SEMANTICS] `rights.grant` and `rights.revoke` answer with the user's rights as listed after the change, not with
    // what changed (`LedgerApiAdministration.users.rights`: the command, then `Rights.List`; measured: `revoke(participantAdmin = true)`
    // prints `participantAdmin` false)
    let list_rights = |id: &str| -> Result<Value, String> {
        let (status, body) = call_json(host, port, "GET", &format!("/v2/users/{id}/rights"), None)?;
        if (200..300).contains(&status) {
            Ok(user_rights(&body["rights"]))
        } else {
            Err(format!("{node}.{path}: rights: {}", error_cause(&body)))
        }
    };
    let rights_json = |act_as: &[String], read_as: &[String], admin: bool| -> Vec<Json> {
        let mut rights: Vec<Json> = act_as
            .iter()
            .map(|p| json!({ "kind": { "CanActAs": { "value": { "party": p } } } }))
            .chain(
                read_as
                    .iter()
                    .map(|p| json!({ "kind": { "CanReadAs": { "value": { "party": p } } } })),
            )
            .collect();
        if admin {
            rights.push(json!({ "kind": { "ParticipantAdmin": { "value": {} } } }));
        }
        rights
    };
    let ok = |status: u16, body: &Json, what: &str| -> Result<(), String> {
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err(format!("{node}.{path}: {what}: {}", error_cause(body)))
        }
    };
    match path {
        "health.is_running" => {
            let (status, _) = call(host, port, "GET", "/livez", None)?;
            Ok(Value::Bool(status == 200))
        }
        "ledger_api.state.end" => {
            let (status, body) = call_json(host, port, "GET", "/v2/state/ledger-end", None)?;
            ok(status, &body, "ledger end")?;
            body["offset"]
                .as_i64()
                .map(Value::Long)
                .ok_or_else(|| format!("{node}.{path}: no offset in {body}"))
        }
        "dars.upload" => {
            let file = text_arg(0, "path")?;
            let bytes = std::fs::read(&file).map_err(|e| format!("cannot read {file}: {e}"))?;
            let main = lf_archive::parse_dar_file(Path::new(&file))
                .map_err(|e| format!("{file}: {e}"))?
                .main_package_id;
            let (status, body) = call(
                host,
                port,
                "POST",
                "/v2/packages",
                Some((&bytes, "application/octet-stream")),
            )?;
            ok(status, &body, "upload")?;
            Ok(Value::Text(main))
        }
        "ledger_api.parties.allocate" => {
            let hint = text_arg(0, "party")?;
            let (status, body) = call_json(
                host,
                port,
                "POST",
                "/v2/parties",
                Some(&json!({ "partyIdHint": hint, "identityProviderId": "" })),
            )?;
            ok(status, &body, "allocate")?;
            Ok(party_details(&body["partyDetails"]))
        }
        "ledger_api.parties.list" => {
            let (status, body) = call_json(host, port, "GET", "/v2/parties", None)?;
            ok(status, &body, "list")?;
            Ok(Value::Seq(
                body["partyDetails"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(party_details)
                    .collect(),
            ))
        }
        "ledger_api.packages.list" => {
            let (status, body) = call_json(host, port, "GET", "/v2/packages", None)?;
            ok(status, &body, "list")?;
            Ok(Value::Seq(
                body["packageIds"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|id| {
                        Some(object([(
                            "packageId",
                            Value::Text(id.as_str()?.to_string()),
                        )]))
                    })
                    .collect(),
            ))
        }
        "ledger_api.users.list" => {
            let (status, body) = call_json(host, port, "GET", "/v2/users", None)?;
            ok(status, &body, "list")?;
            let users = body["users"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|u| {
                    object([
                        (
                            "id",
                            Value::Text(u["id"].as_str().unwrap_or_default().into()),
                        ),
                        (
                            "primaryParty",
                            match u["primaryParty"].as_str() {
                                Some(p) if !p.is_empty() => {
                                    Value::Some(Box::new(Value::Text(p.into())))
                                }
                                _ => Value::None,
                            },
                        ),
                    ])
                })
                .collect();
            Ok(object([("users", Value::Seq(users))]))
        }
        "id" => {
            let (status, body) = call_json(host, port, "GET", "/v2/parties/participant-id", None)?;
            ok(status, &body, "participant id")?;
            body["participantId"]
                .as_str()
                .map(|p| Value::Participant(p.to_string()))
                .ok_or_else(|| format!("{node}.{path}: no participantId in {body}"))
        }
        "ledger_api.users.create" => {
            let id = text_arg(0, "id")?;
            let act_as = parties_arg(1, "actAs")?;
            let primary = match args.get(2, "primaryParty") {
                None | Some(Value::None) => None,
                Some(Value::Some(p)) => match p.as_ref() {
                    Value::Party(p) => Some(p.clone()),
                    other => return Err(format!("{node}.{path}: primaryParty: {other:?}")),
                },
                Some(other) => return Err(format!("{node}.{path}: primaryParty: {other:?}")),
            };
            let read_as = parties_arg(3, "readAs")?;
            let admin = bool_arg(4, "participantAdmin")?;
            let (status, body) = call_json(
                host,
                port,
                "POST",
                "/v2/users",
                Some(&json!({
                    "user": {
                        "id": id,
                        "primaryParty": primary.unwrap_or_default(),
                        "isDeactivated": false,
                        "identityProviderId": "",
                    },
                    "rights": rights_json(&act_as, &read_as, admin),
                })),
            )?;
            ok(status, &body, "create")?;
            Ok(user(&body["user"]))
        }
        "ledger_api.users.get" => {
            let id = text_arg(0, "id")?;
            let (status, body) = call_json(host, port, "GET", &format!("/v2/users/{id}"), None)?;
            ok(status, &body, "get")?;
            Ok(user(&body["user"]))
        }
        "ledger_api.users.delete" => {
            let id = text_arg(0, "id")?;
            let (status, body) = call_json(host, port, "DELETE", &format!("/v2/users/{id}"), None)?;
            ok(status, &body, "delete")?;
            Ok(Value::Unit)
        }
        "ledger_api.users.rights.list" => {
            let id = text_arg(0, "id")?;
            let (status, body) =
                call_json(host, port, "GET", &format!("/v2/users/{id}/rights"), None)?;
            ok(status, &body, "rights")?;
            Ok(user_rights(&body["rights"]))
        }
        "ledger_api.users.rights.grant" => {
            let id = text_arg(0, "id")?;
            let act_as = parties_arg(1, "actAs")?;
            let read_as = parties_arg(2, "readAs")?;
            let admin = bool_arg(3, "participantAdmin")?;
            let (status, body) = call_json(
                host,
                port,
                "POST",
                &format!("/v2/users/{id}/rights"),
                Some(&json!({
                    "userId": id,
                    "rights": rights_json(&act_as, &read_as, admin),
                    "identityProviderId": "",
                })),
            )?;
            ok(status, &body, "grant")?;
            list_rights(&id)
        }
        "ledger_api.users.rights.revoke" => {
            let id = text_arg(0, "id")?;
            let act_as = parties_arg(1, "actAs")?;
            let read_as = parties_arg(2, "readAs")?;
            let admin = bool_arg(3, "participantAdmin")?;
            let (status, body) = call_json(
                host,
                port,
                "PATCH",
                &format!("/v2/users/{id}/rights"),
                Some(&json!({
                    "userId": id,
                    "rights": rights_json(&act_as, &read_as, admin),
                    "identityProviderId": "",
                })),
            )?;
            ok(status, &body, "revoke")?;
            list_rights(&id)
        }
        "ledger_api.commands.submit" => {
            let act_as = parties_arg(0, "actAs")?;
            let commands = match args.get(1, "commands") {
                Some(Value::Seq(items)) => items
                    .iter()
                    .map(|c| match c {
                        Value::Command(json) => Ok(json.clone()),
                        other => Err(format!("{node}.{path}: a Command expected, got {other:?}")),
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                other => return Err(format!("{node}.{path}: commands expected, got {other:?}")),
            };
            let command_id = format!(
                "canton-rs-console-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            );
            let mut filters = serde_json::Map::new();
            for p in &act_as {
                filters.insert(p.clone(), wildcard());
            }
            let (status, body) = call_json(
                host,
                port,
                "POST",
                "/v2/commands/submit-and-wait-for-transaction",
                Some(&json!({
                    "commands": {
                        "commands": commands,
                        "commandId": command_id,
                        "actAs": act_as,
                        "userId": "participant_admin",
                    },
                    "transactionFormat": {
                        "eventFormat": { "filtersByParty": filters, "verbose": true },
                        "transactionShape": "TRANSACTION_SHAPE_LEDGER_EFFECTS",
                    },
                })),
            )?;
            ok(status, &body, "submit")?;
            let tx = &body["transaction"];
            Ok(object([
                (
                    "updateId",
                    Value::Text(tx["updateId"].as_str().unwrap_or_default().into()),
                ),
                (
                    "events",
                    Value::Seq(
                        tx["events"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .map(|e| Value::Text(e.to_string()))
                            .collect(),
                    ),
                ),
            ]))
        }
        "ledger_api.state.acs.of_party" => {
            let party = match args.get(0, "party") {
                Some(Value::Party(p)) => p.clone(),
                other => return Err(format!("{node}.{path}: a party expected, got {other:?}")),
            };
            let (status, end) = call_json(host, port, "GET", "/v2/state/ledger-end", None)?;
            ok(status, &end, "ledger end")?;
            let mut filters = serde_json::Map::new();
            filters.insert(party, wildcard());
            let (status, body) = call_json(
                host,
                port,
                "POST",
                "/v2/state/active-contracts",
                Some(&json!({
                    "eventFormat": { "filtersByParty": filters, "verbose": true },
                    "activeAtOffset": end["offset"],
                })),
            )?;
            ok(status, &body, "active contracts")?;
            Ok(Value::Seq(
                body.as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|entry| {
                        let created =
                            entry.pointer("/contractEntry/JsActiveContract/createdEvent")?;
                        Some(object([
                            (
                                "contractId",
                                Value::Text(created["contractId"].as_str()?.into()),
                            ),
                            (
                                "templateId",
                                Value::Text(created["templateId"].as_str()?.into()),
                            ),
                        ]))
                    })
                    .collect(),
            ))
        }
        "ledger_api.identity_provider_config.list" => {
            let (status, body) = call_json(host, port, "GET", "/v2/idps", None)?;
            ok(status, &body, "list")?;
            Ok(Value::Seq(
                body["identityProviderConfigs"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|c| {
                        object([(
                            "identityProviderId",
                            Value::Text(
                                c["identityProviderId"].as_str().unwrap_or_default().into(),
                            ),
                        )])
                    })
                    .collect(),
            ))
        }
        _ if inventory_has("participant", path) => Err(format!(
            "{node}.{path} is a Canton 3.7.2 console command this console does not serve"
        )),
        _ => Err(format!(
            "{node}.{path} is not a Canton 3.7.2 console command"
        )),
    }
}

/// A `User`: `id`, `primaryParty` (`Option[PartyId]`), `isDeactivated`.
fn user(u: &Json) -> Value {
    object([
        (
            "id",
            Value::Text(u["id"].as_str().unwrap_or_default().into()),
        ),
        (
            "primaryParty",
            match u["primaryParty"].as_str() {
                Some(p) if !p.is_empty() => Value::Some(Box::new(Value::Party(p.into()))),
                _ => Value::None,
            },
        ),
        (
            "isDeactivated",
            Value::Bool(u["isDeactivated"].as_bool().unwrap_or(false)),
        ),
    ])
}

/// `UserRights`: `actAs`, `readAs` (sets of parties), `participantAdmin`, `identityProviderAdmin`, `readAsAnyParty`.
fn user_rights(rights: &Json) -> Value {
    let (mut act_as, mut read_as) = (Vec::new(), Vec::new());
    let (mut admin, mut idp_admin, mut any) = (false, false, false);
    for right in rights.as_array().into_iter().flatten() {
        let Some((kind, inner)) = right["kind"].as_object().and_then(|o| o.iter().next()) else {
            continue;
        };
        let party = || Value::Party(inner["value"]["party"].as_str().unwrap_or_default().into());
        match kind.as_str() {
            "CanActAs" => act_as.push(party()),
            "CanReadAs" => read_as.push(party()),
            "ParticipantAdmin" => admin = true,
            "IdentityProviderAdmin" => idp_admin = true,
            "CanReadAsAnyParty" => any = true,
            _ => {}
        }
    }
    object([
        ("actAs", Value::Seq(act_as)),
        ("readAs", Value::Seq(read_as)),
        ("participantAdmin", Value::Bool(admin)),
        ("identityProviderAdmin", Value::Bool(idp_admin)),
        ("readAsAnyParty", Value::Bool(any)),
    ])
}

fn wildcard() -> Json {
    json!({ "cumulative": [{ "identifierFilter": { "WildcardFilter": { "value": { "includeCreatedEventBlob": false } } } }] })
}

fn party_details(p: &Json) -> Value {
    object([
        (
            "party",
            Value::Party(p["party"].as_str().unwrap_or_default().into()),
        ),
        (
            "isLocal",
            Value::Bool(p["isLocal"].as_bool().unwrap_or(false)),
        ),
    ])
}

fn object<const N: usize>(fields: [(&str, Value); N]) -> Value {
    Value::Object(
        fields
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::parser::tokenize;
    use super::parser::Expr;
    use super::parser::Parser;
    use super::*;

    #[test]
    fn a_path_in_the_inventory_and_one_that_is_not_are_refused_differently() {
        let mut console = Console::new(&["participant1=127.0.0.1:1".into()]).unwrap();
        let served_elsewhere = console
            .run("participant1.topology.party_to_participant_mappings.list(\"x\")")
            .unwrap_err();
        assert!(
            served_elsewhere
                .contains("is a Canton 3.7.2 console command this console does not serve"),
            "{served_elsewhere}"
        );
        let invented = console.run("participant1.made.up()").unwrap_err();
        assert!(
            invented.contains("is not a Canton 3.7.2 console command"),
            "{invented}"
        );
    }

    #[test]
    fn values_steps_and_variables() {
        let mut console = Console::new(&[]).unwrap();
        console.run("val x = \"abc\"").unwrap();
        assert_eq!(console.vars["x"], Value::Text("abc".into()));
        let seq = Value::Seq(vec![
            object([("party", Value::Text("b::1".into()))]),
            object([("party", Value::Text("a::1".into()))]),
        ]);
        let parties = seq.step("map", &[Value::Lambda("party".into())]).unwrap();
        let sorted = parties.clone().step("sorted", &[]).unwrap();
        assert_eq!(sorted.show(), "List(a::1, b::1)");
        assert_eq!(
            sorted.step("mkString", &[Value::Text(",".into())]).unwrap(),
            Value::Text("a::1,b::1".into())
        );
        assert_eq!(parties.step("size", &[]).unwrap(), Value::Long(2));
        assert!(console.run("println(nothing)").is_err());
        // collections and options as arguments are written the Scala way
        console.run("val s = Set(\"a\", \"b\")").unwrap();
        assert_eq!(
            console.vars["s"],
            Value::Seq(vec![Value::Text("a".into()), Value::Text("b".into())])
        );
        console.run("val o = Some(\"x\")").unwrap();
        assert_eq!(console.vars["o"].show(), "Some(x)");
        console.run("val n = None").unwrap();
        assert_eq!(console.vars["n"].show(), "None");
        // a named argument parses as one
        let tokens = tokenize("f.g(id = \"carol\", Set())").unwrap();
        let expr = Parser { tokens, at: 0 }.expr().unwrap();
        let Expr::Path { steps, .. } = expr else {
            panic!()
        };
        let args = steps[0].args.as_ref().unwrap();
        assert_eq!(args[0].name.as_deref(), Some("id"));
        assert_eq!(args[1].name, None);
        // a Map literal and a command built from it, without any node
        console
            .run("val c = ledger_api_utils.create(\"pkg\", \"M\", \"T\", Map(\"text\" -> \"hi\", \"n\" -> 2))")
            .unwrap();
        assert_eq!(
            console.vars["c"],
            Value::Command(json!({ "CreateCommand": {
                "templateId": "pkg:M:T",
                "createArguments": { "n": "2", "text": "hi" },
            }}))
        );
        let unserved = console.run("ledger_api_utils.help(\"x\")").unwrap_err();
        assert!(
            unserved.contains("this console does not serve"),
            "{unserved}"
        );
        // a party prints as the console prints a `PartyId`, and compares whole
        let ns = format!("1220{}", "ab".repeat(32));
        let alice = Value::Party(format!("alice::{ns}"));
        assert_eq!(alice.show(), "alice::1220abababab...");
        assert_eq!(
            alice.clone().step("toProtoPrimitive", &[]).unwrap(),
            Value::Text(format!("alice::{ns}"))
        );
        assert_eq!(
            Value::Seq(vec![alice.clone()])
                .step("contains", &[alice])
                .unwrap(),
            Value::Bool(true)
        );
        // Official Canton 3.7.2 inventory validation for new console attach lifecycle & top-level paths
        assert!(inventory_has("participant", "stop"));
        assert!(inventory_has("participant", "start"));
        assert!(inventory_has("sequencer", "stop"));
        assert!(inventory_has("mediator", "start"));
        assert!(inventory_has("top_level", "participants"));
        assert!(inventory_has("top_level", "health.status"));
        assert!(!inventory_has("participant", "splice.status"));
        assert!(!inventory_has("top_level", "xray.trace"));
    }
}
