/// What the bootstrap script says.
#[derive(Debug, PartialEq, Eq)]
pub struct Bootstrap {
    pub synchronizer_name: String,
    /// `(node, sequencer_or_url, alias)` of each `connect_local` / `connect_local_bft` / `connect_bft`.
    pub connections: Vec<(String, String, String)>,
    /// Sequencer or owner names listed in `synchronizerOwners = Seq(...)`.
    pub owners: Vec<String>,
    /// `synchronizerThreshold` (default 1 when omitted).
    pub threshold: i32,
    /// `(from_node, target_node)` pairs from `<node>.health.ping(<target>)`.
    pub pings: Vec<(String, String)>,
}

/// The calls a bootstrap script may make (the identifier chains before a `(`, with the node's name read as `<node>`).
const KNOWN_CALLS: [&str; 19] = [
    "<node>.synchronizers.list_connected",
    "bootstrap.synchronizer",
    "<node>.synchronizers.connect_local",
    "<node>.synchronizers.connect_local_bft",
    "<node>.synchronizers.connect_bft",
    "<node>.synchronizers.active",
    "<node>.health.ping",
    "nodes.local.start",
    "Seq",
    "GrpcSequencerConnection.tryCreate",
    "SequencerAlias.tryCreate",
    "StaticSynchronizerParameters.defaultsWithoutKMS",
    "StaticSynchronizerParameters.defaults",
    "ProtocolVersion.forSynchronizer",
    "PositiveInt.one",
    "PositiveInt.two",
    "PositiveInt.three",
    "PositiveInt.tryCreate",
    "utils.retry_until_true",
];

fn strip_line_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_quotes = false;
    while let Some(c) = chars.next() {
        if in_quotes {
            out.push(c);
            if c == '\\' {
                if let Some(esc) = chars.next() {
                    out.push(esc);
                }
            } else if c == '"' {
                in_quotes = false;
            }
            continue;
        }
        if c == '"' {
            in_quotes = true;
            out.push(c);
        } else if c == '/' && chars.peek() == Some(&'/') {
            for next in chars.by_ref() {
                if next == '\n' {
                    out.push('\n');
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn quoted_strings(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '"' {
            continue;
        }
        let mut cur = String::new();
        while let Some(nc) = chars.next() {
            if nc == '\\' {
                if let Some(esc) = chars.next() {
                    cur.push(esc);
                }
            } else if nc == '"' {
                break;
            } else {
                cur.push(nc);
            }
        }
        out.push(cur);
    }
    out
}

fn after_named_param<'a>(args: &'a str, name: &str) -> Option<&'a str> {
    let bytes = args.as_bytes();
    let mut depth = 0usize;
    let mut in_quotes = false;
    let mut i = 0;
    while i < bytes.len() {
        if in_quotes {
            if bytes[i] == b'\\' {
                i += 2;
                continue;
            }
            if bytes[i] == b'"' {
                in_quotes = false;
            }
            i += 1;
            continue;
        }
        match bytes[i] {
            b'"' => {
                in_quotes = true;
                i += 1;
            }
            b'(' => {
                depth += 1;
                i += 1;
            }
            b')' => {
                depth = depth.saturating_sub(1);
                i += 1;
            }
            _ if depth == 0 && args[i..].starts_with(name) => {
                let prev_ok =
                    i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_');
                let after = &args[i + name.len()..];
                if prev_ok {
                    let trimmed = after.trim_start();
                    if let Some(rest) = trimmed.strip_prefix('=') {
                        return Some(rest.trim_start());
                    }
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    None
}

fn split_top_level_args(args: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let bytes = args.as_bytes();
    let (mut depth, mut in_quotes, mut start) = (0usize, false, 0usize);
    let mut i = 0;
    while i < bytes.len() {
        if in_quotes {
            if bytes[i] == b'\\' {
                i += 2;
                continue;
            }
            if bytes[i] == b'"' {
                in_quotes = false;
            }
            i += 1;
            continue;
        }
        match bytes[i] {
            b'"' => in_quotes = true,
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => {
                out.push(args[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    let tail = args[start..].trim();
    if !tail.is_empty() {
        out.push(tail);
    }
    out
}

fn extract_seq_idents(s: &str) -> Vec<String> {
    let Some(pos) = s.find("Seq(") else {
        return Vec::new();
    };
    let rest = &s[pos + 4..];
    let mut depth = 1usize;
    let mut end = rest.len();
    for (idx, b) in rest.bytes().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    end = idx;
                    break;
                }
            }
            _ => {}
        }
    }
    rest[..end]
        .split(',')
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(String::from)
        .collect()
}

fn parse_threshold_expr(expr: &str) -> Option<i32> {
    let top = split_top_level_args(expr).into_iter().next()?.trim();
    match top {
        "PositiveInt.one" => Some(1),
        "PositiveInt.two" => Some(2),
        "PositiveInt.three" => Some(3),
        other => {
            if let Some(inner) = other
                .strip_prefix("PositiveInt.tryCreate(")
                .and_then(|s| s.strip_suffix(')'))
            {
                inner.trim().parse().ok()
            } else {
                other.parse().ok()
            }
        }
    }
}

/// Reads the statements of the hub's bootstrap script (see the module documentation).
pub fn parse_bootstrap(text: &str, nodes: &[&str]) -> Result<Bootstrap, String> {
    let code = strip_line_comments(text);
    // every identifier chain followed by `(` is a call: each has to be one this reads
    let bytes = code.as_bytes();
    let mut i = 0;
    let (mut synchronizer_name, mut connections, mut owners, mut threshold, mut pings) =
        (None, Vec::new(), Vec::new(), 1i32, Vec::new());
    while i < bytes.len() {
        if bytes[i] == b'"' {
            i += 1;
            while i < bytes.len() && bytes[i] != b'"' {
                if bytes[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
            i += 1;
            continue;
        }
        if !(bytes[i].is_ascii_alphabetic() || bytes[i] == b'_') {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len()
            && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'_' | b'.'))
        {
            i += 1;
        }
        let chain = &code[start..i];
        if bytes.get(i) != Some(&b'(') {
            continue;
        }
        let shown = nodes
            .iter()
            .find_map(|n| {
                chain
                    .strip_prefix(&format!("{n}."))
                    .map(|rest| format!("<node>.{rest}"))
            })
            .unwrap_or_else(|| chain.to_string());
        if !KNOWN_CALLS.contains(&shown.as_str()) {
            return Err(format!(
                "the bootstrap script calls `{chain}`, which the daemon does not run (it reads {})",
                KNOWN_CALLS.join(", ")
            ));
        }
        // the argument text up to the matching `)`
        let mut depth = 0;
        let mut j = i;
        while j < bytes.len() {
            match bytes[j] {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                b'"' => {
                    j += 1;
                    while j < bytes.len() && bytes[j] != b'"' {
                        if bytes[j] == b'\\' {
                            j += 1;
                        }
                        j += 1;
                    }
                }
                _ => {}
            }
            j += 1;
        }
        let args = &code[i + 1..j.min(code.len())];
        if shown == "bootstrap.synchronizer" {
            synchronizer_name = after_named_param(args, "synchronizerName")
                .and_then(|r| quoted_strings(r).into_iter().next())
                .or_else(|| quoted_strings(args).into_iter().next());
            if let Some(r) = after_named_param(args, "synchronizerOwners") {
                owners = extract_seq_idents(r);
            }
            if let Some(r) = after_named_param(args, "synchronizerThreshold") {
                if let Some(t) = parse_threshold_expr(r) {
                    threshold = t;
                }
            }
        }
        if shown == "<node>.synchronizers.connect_local" {
            let node = chain.split('.').next().unwrap_or_default().to_string();
            let sequencer = args.split(',').next().unwrap_or("").trim().to_string();
            let alias = quoted_strings(args).into_iter().next().unwrap_or_default();
            connections.push((node, sequencer, alias));
        }
        if shown == "<node>.synchronizers.connect_local_bft" {
            let node = chain.split('.').next().unwrap_or_default().to_string();
            let seqs = after_named_param(args, "sequencers")
                .map(extract_seq_idents)
                .unwrap_or_else(|| extract_seq_idents(args));
            let chosen = seqs
                .get(connections.len() % seqs.len().max(1))
                .cloned()
                .unwrap_or_default();
            let alias = after_named_param(args, "synchronizerAlias")
                .and_then(|r| quoted_strings(r).into_iter().next())
                .or_else(|| quoted_strings(args).into_iter().next())
                .unwrap_or_default();
            connections.push((node, chosen, alias));
        }
        if shown == "<node>.synchronizers.connect_bft" {
            let node = chain.split('.').next().unwrap_or_default().to_string();
            let top = split_top_level_args(args);
            let seq_arg = after_named_param(args, "connections")
                .unwrap_or_else(|| top.first().copied().unwrap_or(""));
            let urls: Vec<String> = quoted_strings(seq_arg)
                .into_iter()
                .filter(|s| s.starts_with("http://") || s.starts_with("https://"))
                .collect();
            let chosen = urls
                .get(connections.len() % urls.len().max(1))
                .cloned()
                .unwrap_or_default();
            let alias = after_named_param(args, "synchronizerAlias")
                .and_then(|r| quoted_strings(r).into_iter().next())
                .or_else(|| {
                    top.iter()
                        .skip(1)
                        .find_map(|part| quoted_strings(part).into_iter().next())
                })
                .unwrap_or_default();
            connections.push((node, chosen, alias));
        }
        if shown == "<node>.health.ping" {
            let from = chain.split('.').next().unwrap_or_default().to_string();
            let to = split_top_level_args(args)
                .into_iter()
                .next()
                .unwrap_or("")
                .trim_matches('"')
                .to_string();
            if !to.is_empty() {
                pings.push((from, to));
            }
        }
        i = start + chain.len();
    }
    Ok(Bootstrap {
        synchronizer_name: synchronizer_name.ok_or(
            "the bootstrap script has no bootstrap.synchronizer(synchronizerName = \"...\")",
        )?,
        connections,
        owners,
        threshold,
        pings,
    })
}
