#!/usr/bin/env python3
"""G11: an audit of the product that can fail.

    scripts/audit-native.py              run the four checks on the product; exit 1 when any fails
    scripts/audit-native.py --selftest   show that each check fails on a planted violation (and passes on what is allowed)

The checks, one per condition of the gate (JVM-free, no foreign helper, native code accounted for, one executable with every role):

  libraries  every shared library each product binary links is the operating system's (`canton-rs localnet audit --binary`; no JVM library).
  spawns     the product crates start no process except those in tests/oracle/native-audit/allowed-exec.tsv (a source scan of every crate the
             product binaries depend on, for `Command::new` and `process::Command`). An allowed entry nothing uses any more fails too.
  native     the crates in the product's dependency closure that bring C code (a `links` key, or a build dependency on `cc` or `cmake`) are
             exactly those of tests/oracle/native-audit/allowed-native.tsv, each with its reason.
  roles      for each role of the product, the one executable `canton-rs` serves it: its serving command opens a port. A role no command of
             `canton-rs` serves, or whose command prints a status and exits, is not served.

Nothing here prints a constant: every line comes from a measurement.
"""
import json, os, re, socket, subprocess, sys, tempfile, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUDIT = os.path.join(ROOT, "tests/oracle/native-audit")
PRODUCT_BINARIES = ["canton-rs", "rust-sequencer", "ledger-json-api", "ledger-grpc-server"]
# the roles of the product and the command of the one executable that serves each (`{port}` is a free port); None: no such command
ROLES = [
    ("sequencer", ["sequencer", "run", "--port", "{port}"]),
    # a mediator process with its own identity (`{statedir}`: the mediator's own state directory), onboarded by the operator first (S-LOCAL-011)
    ("mediator", ["mediator", "run", "--port", "{port}", "--sequencer-url", "{sequencer}", "--state-dir", "{statedir}"]),
    # a participant needs a synchronizer to join: the audit starts a sequencer for it (`{sequencer}` is its URL)
    ("participant", ["participant", "run", "--port", "{port}", "--sequencer", "{sequencer}", "--dar", "contracts/target/sample-contract.dar"]),
    ("ledger-api (gRPC)", ["ledger-api", "--port", "{port}"]),
    ("json-api", ["json-api", "--port", "{port}"]),
    ("splice apps", ["splice", "serve", "--port", "{port}", "--dar-dir", "tests/oracle/splice-dars"]),
]


def run(args, **kw):
    return subprocess.run(args, capture_output=True, text=True, **kw)


def table(path):
    rows = {}
    for line in open(path):
        line = line.rstrip("\n")
        if line and not line.startswith("#"):
            key, _, reason = line.partition("\t")
            rows[key] = reason
    return rows


# ---- libraries ----------------------------------------------------------------------------------------------------------------------
def libraries(binaries, canton_rs):
    problems = []
    for name in binaries:
        path = os.path.join(ROOT, "target/debug", name)
        if not os.path.exists(path):
            problems.append(f"{name}: not built")
            continue
        out = run([canton_rs, "localnet", "audit", "--binary", path])
        linked = [l.strip() for l in out.stdout.splitlines() if l.strip().startswith("links ")]
        print(f"   {name}: {len(linked)} libraries, " + ("all system" if out.returncode == 0 else "FOREIGN"))
        if out.returncode != 0:
            problems.append(f"{name}: " + (out.stderr.strip() or out.stdout.strip()).splitlines()[-1])
    return problems


# ---- spawns -------------------------------------------------------------------------------------------------------------------------
def product_crates():
    host = re.search(r"^host: (.*)$", run(["rustc", "-vV"]).stdout, re.M).group(1)
    meta = json.loads(run(["cargo", "metadata", "--format-version", "1", "--offline", "--filter-platform", host], cwd=ROOT).stdout)
    by_id = {p["id"]: p for p in meta["packages"]}
    resolve = {n["id"]: n for n in meta["resolve"]["nodes"]}
    roots = [p["id"] for p in meta["packages"] if p["name"] in {"canton-rs", "canton-sequencer-server", "ledger-json-api", "ledger-grpc-api"}]
    seen, stack = set(), list(roots)
    while stack:
        i = stack.pop()
        if i in seen:
            continue
        seen.add(i)
        for d in resolve[i]["deps"]:
            if any(k["kind"] in (None, "normal") for k in d["dep_kinds"]):
                stack.append(d["pkg"])
    return [by_id[i] for i in seen], by_id


def strip_test_items(text):
    """The source without its `#[cfg(test)]` items (each up to its `;` or its closing brace); line numbers are kept."""
    out, at = [], 0
    attr = re.compile(r"^[ \t]*#\[cfg\(test\)\]", re.M)
    while (m := attr.search(text, at)) is not None:
        out.append(text[at:m.start()])
        i, depth = m.end(), 0
        while i < len(text):
            c = text[i]
            if text.startswith("//", i):
                i = text.find("\n", i)
                i = len(text) if i < 0 else i
                continue
            if text.startswith("/*", i):
                i = text.find("*/", i + 2)
                i = len(text) if i < 0 else i + 2
                continue
            if c == '"':
                i += 1
                while i < len(text) and text[i] != '"':
                    i += 2 if text[i] == "\\" else 1
            elif c == "'" and re.match(r"'(\\.|[^\\'])'", text[i:i + 4]):
                i = text.index("'", i + 1)
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    i += 1
                    break
            elif c == ";" and depth == 0:
                i += 1
                break
            i += 1
        out.append("\n" * text.count("\n", m.start(), i))
        at = i
    out.append(text[at:])
    return "".join(out)


def scan_spawns(src_dirs, root):
    """The product sources that start a process: path (relative to root) -> the lines."""
    found = {}
    pattern = re.compile(r"\b(?:std::process::)?Command::new\(|process::Command\b")
    for src in src_dirs:
        for base, _, files in os.walk(src):
            for f in files:
                if f.endswith(".rs"):
                    path = os.path.join(base, f)
                    # what is in `#[cfg(test)]` modules is not the product
                    text = strip_test_items(open(path).read())
                    hits = [n + 1 for n, line in enumerate(text.splitlines()) if pattern.search(line) and not line.lstrip().startswith("//")]
                    if hits:
                        found[os.path.relpath(path, root)] = hits
    return found


def spawns(root, allowed, src_dirs=None):
    if src_dirs is None:
        src_dirs = [
            os.path.join(os.path.dirname(p["manifest_path"]), "src")
            for p in product_crates()[0]
            if p["manifest_path"].startswith(root)  # a crate of this product, not of the registry
        ]
    found = scan_spawns(src_dirs, root)
    problems = [f"{path} (lines {hits}) starts a process and is not allowed" for path, hits in sorted(found.items()) if path not in allowed]
    problems += [f"{path} is allowed to start a process and does not" for path in sorted(allowed) if path not in found]
    for path in sorted(found):
        print(f"   {path}: {len(found[path])} spawn(s), " + ("allowed: " + allowed[path] if path in allowed else "NOT ALLOWED"))
    if not found:
        print("   no product source starts a process")
    return problems


# ---- native code --------------------------------------------------------------------------------------------------------------------
def native(allowed):
    packages, by_id = product_crates()
    found = {}
    for p in packages:
        builds_c = any(d["name"] in ("cc", "cmake") and d["kind"] == "build" for d in p["dependencies"])
        if p.get("links") or builds_c:
            found[p["name"]] = p.get("links") or "builds C code"
    problems = [f"{name} ({how}) brings native code and is not accounted for" for name, how in sorted(found.items()) if name not in allowed]
    problems += [f"{name} is accounted for as native code and is not in the product" for name in sorted(allowed) if name not in found]
    for name in sorted(found):
        print(f"   {name}: {found[name]}, " + ("accounted: " + allowed[name] if name in allowed else "NOT ACCOUNTED"))
    return problems


# ---- roles --------------------------------------------------------------------------------------------------------------------------
def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_open(port, child=None, tries=60):
    for _ in range(tries):
        if child is not None and child.poll() is not None:
            return False
        with socket.socket() as s:
            s.settimeout(0.2)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.1)
    return False


def stop(child):
    if child is not None and child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()


def serves(canton_rs, argv):
    port = free_port()
    sequencer = None
    seq_url = ""
    statedir = tempfile.mkdtemp(prefix="audit-state-") if any("{statedir}" in a for a in argv) else ""
    if any("{sequencer}" in a for a in argv):
        seq_port = free_port()
        seq_argv = [canton_rs, "sequencer", "run", "--bind", "127.0.0.1", "--port", str(seq_port), "--name", "auditsync"]
        sequencer = subprocess.Popen(seq_argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not wait_open(seq_port, sequencer):
            stop(sequencer)
            return False
        seq_url = f"http://127.0.0.1:{seq_port}"
        if statedir:
            # the mediator shares nothing with the sequencer: its own identity, which the operator onboards as group 0's mediator
            onboarding = os.path.join(statedir, "onboarding.txt")
            for step in (["mediator", "init", "--state-dir", statedir],
                         ["mediator", "onboarding", "--state-dir", statedir, "--out", onboarding],
                         ["sequencer", "add-mediator", "--sequencer-url", seq_url, "--onboarding", onboarding, "--group", "0", "--replace"]):
                if subprocess.run([canton_rs] + step, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
                    stop(sequencer)
                    return False
    args = [a.replace("{port}", str(port)).replace("{sequencer}", seq_url).replace("{statedir}", statedir) for a in argv]
    child = subprocess.Popen([canton_rs] + args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=ROOT)
    try:
        # a participant joins the synchronizer first (about a second), then listens
        return wait_open(port, child, tries=300)
    finally:
        stop(child)
        stop(sequencer)


def roles(canton_rs, table):
    problems = []
    for role, argv in table:
        if argv is None:
            print(f"   {role}: no command of canton-rs serves it")
            problems.append(f"{role}: no command of canton-rs serves it")
        elif serves(canton_rs, argv):
            print(f"   {role}: `canton-rs {' '.join(argv[:2])}` listens")
        else:
            print(f"   {role}: `canton-rs {' '.join(argv[:2])}` does not listen")
            problems.append(f"{role}: `canton-rs {' '.join(argv[:2])}` opens no port")
    return problems


# ---- the product --------------------------------------------------------------------------------------------------------------------
def audit():
    canton_rs = os.path.join(ROOT, "target/debug/canton-rs")
    build = run(["cargo", "build", "-q", "--offline", "-p", "canton-rs", "-p", "canton-sequencer-server", "-p", "ledger-json-api", "-p", "ledger-grpc-api"], cwd=ROOT)
    if build.returncode != 0:
        sys.exit("the product does not build:\n" + build.stderr)
    failed = {}
    for name, check in [
        ("libraries", lambda: libraries(PRODUCT_BINARIES, canton_rs)),
        ("spawns", lambda: spawns(ROOT, table(os.path.join(AUDIT, "allowed-exec.tsv")))),
        ("native", lambda: native(table(os.path.join(AUDIT, "allowed-native.tsv")))),
        ("roles", lambda: roles(canton_rs, ROLES)),
    ]:
        print(f"== {name}")
        problems = check()
        for p in problems:
            print(f"   FAIL: {p}")
        if problems:
            failed[name] = problems
    print("== verdict")
    for name in ("libraries", "spawns", "native", "roles"):
        print(f"   {name}: {'FAIL' if name in failed else 'ok'}")
    return failed


# ---- self test: every check fails on a planted violation ---------------------------------------------------------------------------
def selftest():
    canton_rs = os.path.join(ROOT, "target/debug/canton-rs")
    ok = True

    def expect(label, problems, wanted):
        nonlocal ok
        good = bool(problems) if wanted == "fail" else not problems
        ok &= good
        print(f"   {'ok ' if good else 'BAD'} {label}: {'failed' if problems else 'passed'}" + (f" ({problems[0]})" if problems else ""))

    print("== libraries: a binary that links a JVM library is refused")
    with tempfile.TemporaryDirectory() as d:
        # canton-rs's own parser, on the output of the platform's tool for a library list that names libjvm: its unit test; here the
        # tool's refusal of a file that is no binary must also be an error and never a pass
        junk = os.path.join(d, "not-a-binary")
        open(junk, "w").write("x")
        out = run([canton_rs, "localnet", "audit", "--binary", junk])
        expect("a file that is no binary", [out.stderr] if out.returncode != 0 else [], "fail")
    out = run(["cargo", "test", "-q", "--offline", "-p", "canton-rs", "--bin", "canton-rs", "libraries_are_read_and_a_foreign_one_is_found"], cwd=ROOT)
    expect("libjvm in the library list (unit test of the classifier)", [] if out.returncode == 0 else [out.stdout[-200:]], "pass")

    print("== spawns: a source that starts a process and is not allowed")
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "src"))
        open(os.path.join(d, "src/lib.rs"), "w").write('fn f() { std::process::Command::new("java").spawn().ok(); }\n')
        expect("Command::new(\"java\") in a product source", spawns(d, {}, [os.path.join(d, "src")]), "fail")
        open(os.path.join(d, "src/lib.rs"), "w").write('fn f() {}\n#[cfg(test)]\nmod t { fn g() { std::process::Command::new("java"); } }\n')
        expect("a spawn only in a test module", spawns(d, {}, [os.path.join(d, "src")]), "pass")
        open(os.path.join(d, "src/lib.rs"), "w").write('#[cfg(test)]\nfn helper() {}\nfn f() { std::process::Command::new("java"); }\n')
        expect("a spawn after a test-only function", spawns(d, {}, [os.path.join(d, "src")]), "fail")
    expect("an allowed entry nothing uses", spawns(ROOT, {**table(os.path.join(AUDIT, "allowed-exec.tsv")), "crates/none/src/gone.rs": "x"}), "fail")

    print("== native: code the table does not account for, and a stale entry")
    expect("no table at all", native({}), "fail")
    expect("a stale entry", native({**table(os.path.join(AUDIT, "allowed-native.tsv")), "nothing-sys": "x"}), "fail")

    print("== roles: a command that prints and exits, and a role no command serves")
    expect("mediator (prints a status and exits)", roles(canton_rs, [("mediator", ["mediator", "run", "--port", "{port}"])]), "fail")
    expect("a role without a command", roles(canton_rs, [("none", None)]), "fail")
    expect("sequencer (serves)", roles(canton_rs, [("sequencer", ["sequencer", "run", "--port", "{port}"])]), "pass")
    return ok


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(0 if selftest() else 1)
    failed = audit()
    sys.exit(1 if failed else 0)
