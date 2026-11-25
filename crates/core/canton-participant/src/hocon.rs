//! A reader for the HOCON subset Canton's `canton.conf` is written in (U-47, REQ-JDBC-CONFIG-001): objects (braced or the bare root), `key = value`,
//! `key: value`, `key { ... }`, `key += elem`, dotted keys, arrays, quoted and unquoted strings, numbers, booleans, `null`, `#` and `//` comments,
//! newline or comma separators, `include` directives (`"path"`, `file("path")`, `required(...)`) in [`parse_file`], and `${NAME}` / `${path.to.key}`
//! / `${?optional}` substitutions (including whole-object/array substitutions).
//!
//! [CANTON-NOTE: LIMITATION] Still not full HOCON: triple-quoted strings, `url(...)` / `classpath(...)` includes, and `include` in string-only
//! [`parse`] (without a base directory) are explicitly rejected with `Err` rather than guessed.
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// A parsed value. Objects keep the order of their keys' first appearance.
#[derive(Debug, Clone, PartialEq)]
pub enum Hocon {
    Object(Vec<(String, Hocon)>),
    Array(Vec<Hocon>),
    Str(String),
    /// A number as written (`6502`, `0.5`).
    Num(String),
    Bool(bool),
    Null,
}

impl Hocon {
    /// The value at a dotted path (`canton.participants.p1.storage`), `None` when any step is missing.
    pub fn get(&self, path: &str) -> Option<&Hocon> {
        let mut at = self;
        for part in path.split('.') {
            match at {
                Hocon::Object(fields) => at = &fields.iter().find(|(k, _)| k == part)?.1,
                _ => return None,
            }
        }
        Some(at)
    }

    /// A string, number or boolean as text.
    pub fn text(&self) -> Option<String> {
        match self {
            Hocon::Str(s) | Hocon::Num(s) => Some(s.clone()),
            Hocon::Bool(b) => Some(b.to_string()),
            _ => None,
        }
    }

    pub fn as_u16(&self) -> Option<u16> {
        self.text()?.parse().ok()
    }

    /// The keys of an object, in order.
    pub fn keys(&self) -> Vec<&str> {
        match self {
            Hocon::Object(fields) => fields.iter().map(|(k, _)| k.as_str()).collect(),
            _ => Vec::new(),
        }
    }

    /// The dotted path of every scalar below this value (an array element is `[]`): what a configuration sets, key by key.
    pub fn leaf_paths(&self, prefix: &str) -> Vec<String> {
        match self {
            Hocon::Object(fields) => fields
                .iter()
                .flat_map(|(k, v)| {
                    let path = if prefix.is_empty() {
                        k.clone()
                    } else {
                        format!("{prefix}.{k}")
                    };
                    v.leaf_paths(&path)
                })
                .collect(),
            Hocon::Array(items) => items
                .iter()
                .flat_map(|v| v.leaf_paths(&format!("{prefix}[]")))
                .collect(),
            _ => vec![prefix.to_string()],
        }
    }

    /// The text of every scalar field of an object (`properties { serverName = "db", portNumber = 5432 }` as pairs).
    pub fn scalars(&self) -> BTreeMap<String, String> {
        match self {
            Hocon::Object(fields) => fields
                .iter()
                .filter_map(|(k, v)| Some((k.clone(), v.text()?)))
                .collect(),
            _ => BTreeMap::new(),
        }
    }
}

/// Unresolved intermediate AST supporting post-merge intra-file & environment substitutions.
#[derive(Debug, Clone)]
enum RawHocon {
    Object(Vec<(String, RawHocon)>),
    Array(Vec<RawHocon>),
    Str(String),
    Num(String),
    Bool(bool),
    Null,
    /// Standalone `${path}` or `${?path}` (may resolve to an object, array, or scalar).
    Subst {
        path: String,
        optional: bool,
    },
    /// Composite unquoted text containing literal segments and scalar `${...}` substitutions.
    Concat(Vec<ConcatPart>),
}

#[derive(Debug, Clone)]
enum ConcatPart {
    Literal(String),
    Subst { path: String, optional: bool },
}

struct IncludeState {
    base_dir: PathBuf,
    active_files: BTreeSet<PathBuf>,
}

struct Parser<'a> {
    text: &'a [u8],
    at: usize,
    include_state: Option<&'a mut IncludeState>,
}

/// Parses `text` without a base directory (`include` directives are rejected); `env` answers unresolved `${NAME}` substitutions.
pub fn parse(text: &str, env: &dyn Fn(&str) -> Option<String>) -> Result<Hocon, String> {
    let raw = parse_raw(text, None)?;
    resolve_root(&raw, &raw, env, &mut BTreeSet::new())?.ok_or_else(|| "empty root".to_string())
}

/// Parses a HOCON file at `path`, resolving relative `include` directives, `+=` appends, and `${path}` / `${ENV}` substitutions.
pub fn parse_file(path: &Path, env: &dyn Fn(&str) -> Option<String>) -> Result<Hocon, String> {
    let canon = std::fs::canonicalize(path)
        .map_err(|e| format!("cannot resolve {}: {e}", path.display()))?;
    let base_dir = canon
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let text = std::fs::read_to_string(&canon)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut active_files = BTreeSet::new();
    active_files.insert(canon);
    let mut inc_state = IncludeState {
        base_dir,
        active_files,
    };
    let raw = parse_raw(&text, Some(&mut inc_state))?;
    resolve_root(&raw, &raw, env, &mut BTreeSet::new())?.ok_or_else(|| "empty root".to_string())
}

fn parse_raw(text: &str, include_state: Option<&mut IncludeState>) -> Result<RawHocon, String> {
    let mut p = Parser {
        text: text.as_bytes(),
        at: 0,
        include_state,
    };
    p.skip_space(true);
    let root = if p.peek() == Some(b'{') {
        p.object()?
    } else {
        p.fields(false)?
    };
    p.skip_space(true);
    if p.at < p.text.len() {
        return Err(p.error("text after the end of the configuration"));
    }
    Ok(root)
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.text.get(self.at).copied()
    }

    fn error(&self, what: &str) -> String {
        let line = 1 + self.text[..self.at.min(self.text.len())]
            .iter()
            .filter(|b| **b == b'\n')
            .count();
        format!("line {line}: {what}")
    }

    /// Skips blanks, comments and (when `newlines`) line breaks and commas.
    fn skip_space(&mut self, newlines: bool) {
        while let Some(b) = self.peek() {
            match b {
                b' ' | b'\t' | b'\r' => self.at += 1,
                b'\n' | b',' if newlines => self.at += 1,
                b'#' => self.skip_line(),
                b'/' if self.text.get(self.at + 1) == Some(&b'/') => self.skip_line(),
                _ => break,
            }
        }
    }

    fn skip_line(&mut self) {
        while let Some(b) = self.peek() {
            if b == b'\n' {
                break;
            }
            self.at += 1;
        }
    }

    fn object(&mut self) -> Result<RawHocon, String> {
        self.at += 1; // `{`
        let value = self.fields(true)?;
        self.skip_space(true);
        if self.peek() != Some(b'}') {
            return Err(self.error("an object is not closed with `}`"));
        }
        self.at += 1;
        Ok(value)
    }

    /// Returns `true` when positioned at an unquoted `include` directive (followed by space/`(`/`"`).
    fn at_include_directive(&self) -> bool {
        let rest = &self.text[self.at..];
        if !rest.starts_with(b"include") {
            return false;
        }
        matches!(rest.get(7).copied(), Some(b' ' | b'\t' | b'"' | b'('))
    }

    /// Parses `include [required(] [file(]"path"[)][)]` and merges included fields into `root`.
    fn parse_include(&mut self, root: &mut Vec<(String, RawHocon)>) -> Result<(), String> {
        self.at += b"include".len();
        self.skip_space(false);

        let mut required = false;
        if self.text[self.at..].starts_with(b"required")
            && matches!(
                self.text.get(self.at + 8).copied(),
                Some(b' ' | b'\t' | b'(')
            )
        {
            self.at += 8;
            self.skip_space(false);
            if self.peek() != Some(b'(') {
                return Err(self.error("expected `(` after `required`"));
            }
            self.at += 1;
            self.skip_space(false);
            required = true;
        }

        let mut close_parens = usize::from(required);
        for unsupported in [b"url".as_slice(), b"classpath".as_slice()] {
            if self.text[self.at..].starts_with(unsupported)
                && matches!(
                    self.text.get(self.at + unsupported.len()).copied(),
                    Some(b' ' | b'\t' | b'(')
                )
            {
                let label = std::str::from_utf8(unsupported).unwrap_or("include");
                return Err(self.error(&format!("`include {label}(...)` is not supported")));
            }
        }
        if self.text[self.at..].starts_with(b"file")
            && matches!(
                self.text.get(self.at + 4).copied(),
                Some(b' ' | b'\t' | b'(')
            )
        {
            self.at += 4;
            self.skip_space(false);
            if self.peek() != Some(b'(') {
                return Err(self.error("expected `(` after `file`"));
            }
            self.at += 1;
            self.skip_space(false);
            close_parens += 1;
        }

        if self.peek() != Some(b'"') {
            return Err(self.error("expected quoted path in `include`"));
        }
        let target = self.quoted()?;
        for _ in 0..close_parens {
            self.skip_space(false);
            if self.peek() != Some(b')') {
                return Err(self.error("expected `)` closing `include` qualifier"));
            }
            self.at += 1;
        }

        let (resolved, current_base_dir) = {
            let Some(state) = self.include_state.as_deref() else {
                return Err(self.error("`include` is not read without a file path"));
            };
            (
                resolve_include_path(&state.base_dir, &target),
                state.base_dir.clone(),
            )
        };
        let Some(candidate) = resolved else {
            if required {
                return Err(self.error(&format!(
                    "included required configuration file not found: {target}"
                )));
            }
            return Ok(());
        };

        let canon = std::fs::canonicalize(&candidate)
            .map_err(|e| self.error(&format!("cannot open include {target}: {e}")))?;
        let child_active = {
            let Some(state) = self.include_state.as_deref_mut() else {
                return Err(self.error("`include` is not read without a file path"));
            };
            if !state.active_files.insert(canon.clone()) {
                return Err(self.error(&format!("recursive HOCON include cycle at {target}")));
            }
            state.active_files.clone()
        };

        let inc_text = std::fs::read_to_string(&canon)
            .map_err(|e| self.error(&format!("cannot read include {target}: {e}")));
        let parsed = inc_text.and_then(|txt| {
            let child_base = canon
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or(current_base_dir);
            let mut child_state = IncludeState {
                base_dir: child_base,
                active_files: child_active,
            };
            parse_raw(&txt, Some(&mut child_state))
        });
        if let Some(state) = self.include_state.as_deref_mut() {
            state.active_files.remove(&canon);
        }

        let RawHocon::Object(inc_fields) = parsed? else {
            return Err(self.error("included configuration root must be an object"));
        };
        for (k, v) in inc_fields {
            insert(root, &[k], v)?;
        }
        Ok(())
    }

    /// The fields up to the closing `}` (`braced`) or the end of the text.
    fn fields(&mut self, braced: bool) -> Result<RawHocon, String> {
        let mut root: Vec<(String, RawHocon)> = Vec::new();
        loop {
            self.skip_space(true);
            match self.peek() {
                None if !braced => break,
                None => return Err(self.error("the text ends inside an object")),
                Some(b'}') if braced => break,
                Some(b'}') => return Err(self.error("a `}` without a `{`")),
                _ => {}
            }
            if self.at_include_directive() {
                self.parse_include(&mut root)?;
                continue;
            }
            let key = self.key()?;
            self.skip_space(false);
            match self.peek() {
                Some(b'{') => {
                    let value = self.object()?;
                    insert(&mut root, &key, value)?;
                }
                Some(b'=') | Some(b':') => {
                    self.at += 1;
                    self.skip_space(false);
                    let value = self.value()?;
                    insert(&mut root, &key, value)?;
                }
                Some(b'+') if self.text.get(self.at + 1) == Some(&b'=') => {
                    self.at += 2;
                    self.skip_space(false);
                    let elem = self.value()?;
                    append_array(&mut root, &key, elem)?;
                }
                Some(b'+') => return Err(self.error("unexpected `+` after key (expected `+=`)")),
                _ => return Err(self.error(&format!("`{}` has no value", key.join(".")))),
            }
        }
        Ok(RawHocon::Object(root))
    }

    /// A key, split at its dots: `a.b.c`, `"a.b".c`.
    fn key(&mut self) -> Result<Vec<String>, String> {
        let mut parts = Vec::new();
        let mut current = String::new();
        loop {
            match self.peek() {
                Some(b'"') => current.push_str(&self.quoted()?),
                Some(b) if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'$') => {
                    current.push(b as char);
                    self.at += 1;
                }
                Some(b'.') => {
                    parts.push(std::mem::take(&mut current));
                    self.at += 1;
                }
                _ => break,
            }
        }
        if current.is_empty() && parts.is_empty() {
            return Err(self.error("a key was expected"));
        }
        parts.push(current);
        if parts.iter().any(String::is_empty) {
            return Err(self.error("an empty key"));
        }
        Ok(parts)
    }

    fn value(&mut self) -> Result<RawHocon, String> {
        match self.peek() {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') if self.text[self.at..].starts_with(b"\"\"\"") => {
                Err(self.error("triple-quoted strings are not read"))
            }
            Some(b'"') => Ok(RawHocon::Str(self.quoted()?)),
            _ => self.unquoted(),
        }
    }

    fn array(&mut self) -> Result<RawHocon, String> {
        self.at += 1; // `[`
        let mut items = Vec::new();
        loop {
            self.skip_space(true);
            match self.peek() {
                Some(b']') => {
                    self.at += 1;
                    break;
                }
                None => return Err(self.error("an array is not closed with `]`")),
                _ => items.push(self.value()?),
            }
        }
        Ok(RawHocon::Array(items))
    }

    fn quoted(&mut self) -> Result<String, String> {
        self.at += 1; // `"`
        let mut out = Vec::new();
        loop {
            match self.peek() {
                None => return Err(self.error("a string is not closed")),
                Some(b'"') => {
                    self.at += 1;
                    break;
                }
                Some(b'\\') => {
                    let escaped = self.text.get(self.at + 1).copied();
                    out.push(match escaped {
                        Some(b'n') => b'\n',
                        Some(b't') => b'\t',
                        Some(b'r') => b'\r',
                        Some(b'"') => b'"',
                        Some(b'\\') => b'\\',
                        Some(b'/') => b'/',
                        _ => return Err(self.error("an escape this reader does not know")),
                    });
                    self.at += 2;
                }
                Some(b) => {
                    out.push(b);
                    self.at += 1;
                }
            }
        }
        String::from_utf8(out).map_err(|e| e.to_string())
    }

    /// An unquoted value: up to a line break, a comma, a `}` or `]` or a comment, preserving `${...}` substitutions.
    fn unquoted(&mut self) -> Result<RawHocon, String> {
        let mut parts: Vec<ConcatPart> = Vec::new();
        let mut literal = String::new();
        while let Some(b) = self.peek() {
            match b {
                b'\n' | b',' | b'}' | b']' | b'#' => break,
                // `//` starts a comment, but `://` is part of a URL
                b'/' if self.text.get(self.at + 1) == Some(&b'/') && !literal.ends_with(':') => {
                    break
                }
                b'$' if self.text.get(self.at + 1) == Some(&b'{') => {
                    if !literal.is_empty() {
                        parts.push(ConcatPart::Literal(std::mem::take(&mut literal)));
                    }
                    let close = self.text[self.at..]
                        .iter()
                        .position(|c| *c == b'}')
                        .ok_or_else(|| self.error("a substitution is not closed"))?;
                    let inner = std::str::from_utf8(&self.text[self.at + 2..self.at + close])
                        .map_err(|e| e.to_string())?;
                    let (optional, name) = match inner.strip_prefix('?') {
                        Some(n) => (true, n.trim()),
                        None => (false, inner.trim()),
                    };
                    if name.is_empty() {
                        return Err(self.error("an empty substitution `${}`"));
                    }
                    parts.push(ConcatPart::Subst {
                        path: name.to_string(),
                        optional,
                    });
                    self.at += close + 1;
                }
                _ => {
                    literal.push(b as char);
                    self.at += 1;
                }
            }
        }
        if !literal.is_empty() {
            parts.push(ConcatPart::Literal(literal));
        }

        // Trim leading/trailing whitespace on boundary literal segments
        if let Some(ConcatPart::Literal(first)) = parts.first_mut() {
            let trimmed = first.trim_start().to_string();
            *first = trimmed;
        }
        if let Some(ConcatPart::Literal(last)) = parts.last_mut() {
            let trimmed = last.trim_end().to_string();
            *last = trimmed;
        }
        parts.retain(|p| !matches!(p, ConcatPart::Literal(s) if s.is_empty()));

        if parts.is_empty() {
            return Err(self.error("a value was expected"));
        }
        if parts.len() == 1 {
            return match parts.into_iter().next().expect("checked len == 1") {
                ConcatPart::Subst { path, optional } => Ok(RawHocon::Subst { path, optional }),
                ConcatPart::Literal(text) => Ok(classify_scalar(text)),
            };
        }
        Ok(RawHocon::Concat(parts))
    }
}

fn classify_scalar(text: String) -> RawHocon {
    match text.as_str() {
        "true" => RawHocon::Bool(true),
        "false" => RawHocon::Bool(false),
        "null" => RawHocon::Null,
        t if t.parse::<f64>().is_ok() => RawHocon::Num(text),
        _ => RawHocon::Str(text),
    }
}

fn resolve_include_path(base_dir: &Path, target: &str) -> Option<PathBuf> {
    let direct = base_dir.join(target);
    if direct.is_file() {
        return Some(direct);
    }
    if Path::new(target).extension().is_none() {
        let with_conf = base_dir.join(format!("{target}.conf"));
        if with_conf.is_file() {
            return Some(with_conf);
        }
    }
    None
}

fn raw_get<'a>(root: &'a RawHocon, path: &str) -> Option<&'a RawHocon> {
    let mut at = root;
    for part in path.split('.') {
        match at {
            RawHocon::Object(fields) => {
                at = &fields.iter().rfind(|(k, _)| k == part)?.1;
            }
            _ => return None,
        }
    }
    Some(at)
}

fn resolve_root(
    node: &RawHocon,
    root: &RawHocon,
    env: &dyn Fn(&str) -> Option<String>,
    stack: &mut BTreeSet<String>,
) -> Result<Option<Hocon>, String> {
    match node {
        RawHocon::Object(fields) => {
            let mut out = Vec::with_capacity(fields.len());
            for (k, v) in fields {
                if let Some(resolved) = resolve_root(v, root, env, stack)? {
                    out.push((k.clone(), resolved));
                }
            }
            Ok(Some(Hocon::Object(out)))
        }
        RawHocon::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                if let Some(resolved) = resolve_root(item, root, env, stack)? {
                    out.push(resolved);
                }
            }
            Ok(Some(Hocon::Array(out)))
        }
        RawHocon::Str(s) => Ok(Some(Hocon::Str(s.clone()))),
        RawHocon::Num(n) => Ok(Some(Hocon::Num(n.clone()))),
        RawHocon::Bool(b) => Ok(Some(Hocon::Bool(*b))),
        RawHocon::Null => Ok(Some(Hocon::Null)),
        RawHocon::Subst { path, optional } => {
            if !stack.insert(path.clone()) {
                return Err(format!("cyclic HOCON substitution `${{{path}}}`"));
            }
            let result = if let Some(target) = raw_get(root, path) {
                resolve_root(target, root, env, stack)?
            } else if let Some(val) = env(path) {
                Some(classify_scalar_hocon(val))
            } else if *optional {
                None
            } else {
                return Err(format!(
                    "the substitution `${{{path}}}` has no value in configuration or environment"
                ));
            };
            stack.remove(path);
            Ok(result)
        }
        RawHocon::Concat(parts) => {
            let mut combined = String::new();
            for part in parts {
                match part {
                    ConcatPart::Literal(s) => combined.push_str(s),
                    ConcatPart::Subst { path, optional } => {
                        if !stack.insert(path.clone()) {
                            return Err(format!("cyclic HOCON substitution `${{{path}}}`"));
                        }
                        let fragment = if let Some(target) = raw_get(root, path) {
                            match resolve_root(target, root, env, stack)? {
                                Some(h) => h.text().unwrap_or_default(),
                                None => String::new(),
                            }
                        } else if let Some(val) = env(path) {
                            val
                        } else if *optional {
                            String::new()
                        } else {
                            return Err(format!(
                                "the substitution `${{{path}}}` has no value in configuration or environment"
                            ));
                        };
                        stack.remove(path);
                        combined.push_str(&fragment);
                    }
                }
            }
            Ok(Some(Hocon::Str(combined)))
        }
    }
}

fn classify_scalar_hocon(text: String) -> Hocon {
    match text.as_str() {
        "true" => Hocon::Bool(true),
        "false" => Hocon::Bool(false),
        "null" => Hocon::Null,
        t if t.parse::<f64>().is_ok() => Hocon::Num(text),
        _ => Hocon::Str(text),
    }
}

/// Puts `value` at the dotted `key` of `fields`, merging objects and allowing HOCON scalar/object override.
fn insert(
    fields: &mut Vec<(String, RawHocon)>,
    key: &[String],
    value: RawHocon,
) -> Result<(), String> {
    let (head, rest) = key.split_first().ok_or("an empty key")?;
    let value = if rest.is_empty() {
        value
    } else {
        let mut nested = Vec::new();
        insert(&mut nested, rest, value)?;
        RawHocon::Object(nested)
    };
    match fields.iter_mut().find(|(k, _)| k == head) {
        Some((_, RawHocon::Object(existing))) => match value {
            RawHocon::Object(new) => {
                for (k, v) in new {
                    insert(existing, &[k], v)?;
                }
            }
            other => {
                // [CANTON-NOTE: WHY] When updating an object path with a later scalar or substitution,
                // keep simple override semantics (`*slot = other` at the leaf) matching Typesafe HOCON.
                if let Some(slot) = fields.iter_mut().find(|(k, _)| k == head) {
                    slot.1 = other;
                }
            }
        },
        Some((_, slot)) => *slot = value,
        None => fields.push((head.clone(), value)),
    }
    Ok(())
}

/// Implements HOCON `key += elem`: appends `elem` onto an existing array or creates `[elem]`.
fn append_array(
    fields: &mut Vec<(String, RawHocon)>,
    key: &[String],
    elem: RawHocon,
) -> Result<(), String> {
    let (head, rest) = key.split_first().ok_or("an empty key")?;
    if !rest.is_empty() {
        match fields.iter_mut().find(|(k, _)| k == head) {
            Some((_, RawHocon::Object(existing))) => return append_array(existing, rest, elem),
            Some((_, other)) => {
                return Err(format!(
                    "`{head}` is not an object for `+=` on `{}` ({other:?})",
                    rest.join(".")
                ))
            }
            None => {
                let mut nested = Vec::new();
                append_array(&mut nested, rest, elem)?;
                fields.push((head.clone(), RawHocon::Object(nested)));
                return Ok(());
            }
        }
    }
    match fields.iter_mut().find(|(k, _)| k == head) {
        Some((_, RawHocon::Array(items))) => items.push(elem),
        Some((_, other)) => return Err(format!("`{head}` is not an array for `+=` ({other:?})")),
        None => fields.push((head.clone(), RawHocon::Array(vec![elem]))),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn none(_: &str) -> Option<String> {
        None
    }

    /// The shape of `deploy/hub/canton/canton.conf` of a Canton 3.7.2 participant on PostgreSQL (passwords left out).
    const HUB: &str = r#"
# comment
canton {
  participants {
    participant1 {
      storage {
        type = postgres
        config {
          dataSourceClass = "org.postgresql.ds.PGSimpleDataSource"
          properties {
            serverName = "hub-postgres"
            portNumber = 5432
            databaseName = "hub_participant"
            user = "hub_participant"
            password=secret
          }
        }
        parameters.max-connections = 16
      }
      ledger-api {
        address = "0.0.0.0"
        port = 6501
        auth-services = [{
          type = jwt-rs-256-crt
          certificate = "/hub/auth/jwt.crt"
        }]
      }
      http-ledger-api {
        address = "0.0.0.0"
        port = 6575
      }
    }
  }
}
"#;

    #[test]
    fn the_hub_configuration_is_read() {
        let conf = parse(HUB, &none).unwrap();
        let p = "canton.participants.participant1";
        assert_eq!(
            conf.get(&format!("{p}.storage.type"))
                .unwrap()
                .text()
                .unwrap(),
            "postgres"
        );
        let props = conf
            .get(&format!("{p}.storage.config.properties"))
            .unwrap()
            .scalars();
        assert_eq!(props["serverName"], "hub-postgres");
        assert_eq!(props["portNumber"], "5432");
        assert_eq!(props["databaseName"], "hub_participant");
        assert_eq!(props["password"], "secret");
        assert_eq!(
            conf.get(&format!("{p}.http-ledger-api.port"))
                .unwrap()
                .as_u16(),
            Some(6575)
        );
        assert_eq!(
            conf.get(&format!("{p}.storage.parameters.max-connections"))
                .unwrap()
                .as_u16(),
            Some(16)
        );
        let auth = conf.get(&format!("{p}.ledger-api.auth-services")).unwrap();
        let Hocon::Array(items) = auth else {
            panic!("an array")
        };
        assert_eq!(
            items[0].get("type").unwrap().text().unwrap(),
            "jwt-rs-256-crt"
        );
        assert_eq!(
            conf.get("canton.participants").unwrap().keys(),
            ["participant1"]
        );
    }

    #[test]
    fn substitutions_come_from_the_environment_and_objects_merge() {
        let env = |n: &str| (n == "DB").then(|| "db.internal".to_string());
        let conf = parse(
            "a { host = ${DB}, url = \"x\" }\na { port = 5 }\nb.c = jdbc:postgresql://${DB}:5432/n // trailing\nd = ${?MISSING}x",
            &env,
        )
        .unwrap();
        assert_eq!(conf.get("a.host").unwrap().text().unwrap(), "db.internal");
        assert_eq!(conf.get("a.port").unwrap().text().unwrap(), "5");
        assert_eq!(conf.get("a.url").unwrap().text().unwrap(), "x");
        assert_eq!(
            conf.get("b.c").unwrap().text().unwrap(),
            "jdbc:postgresql://db.internal:5432/n"
        );
        assert_eq!(conf.get("d").unwrap().text().unwrap(), "x");
    }

    #[test]
    fn array_append_and_intra_file_substitutions_work() {
        let conf = parse(
            r#"
            _shared.storage { type = postgres, config.url = "jdbc:postgresql://localhost:5432/canton" }
            canton.participants.p1 {
              storage = ${_shared.storage}
              ledger-api.auth-services = [{ type = jwt-es-256-crt, certificate = "a.crt" }]
              ledger-api.auth-services += { type = jwt-jwks, url = "http://localhost:8080/jwks" }
              optional-auth = ${?_shared.nonexistent}
            }
            "#,
            &none,
        )
        .unwrap();
        assert_eq!(
            conf.get("canton.participants.p1.storage.type")
                .unwrap()
                .text()
                .unwrap(),
            "postgres"
        );
        assert!(conf.get("canton.participants.p1.optional-auth").is_none());
        let Hocon::Array(auth) = conf
            .get("canton.participants.p1.ledger-api.auth-services")
            .unwrap()
        else {
            panic!("expected auth array");
        };
        assert_eq!(auth.len(), 2);
        assert_eq!(auth[1].get("type").unwrap().text().unwrap(), "jwt-jwks");
    }

    #[test]
    fn parse_file_resolves_nested_includes_and_rejects_cycles_and_missing_required() {
        let dir = std::env::temp_dir().join(format!("hocon-inc-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();

        std::fs::write(
            dir.join("sub/shared.conf"),
            r#"
            _shared { storage { type = postgres, config.url = "jdbc:postgresql://127.0.0.1:5432/p1" } }
            canton.participants.p1.http-ledger-api.port = 7575
            "#,
        )
        .unwrap();
        std::fs::write(
            dir.join("sub/nested.conf"),
            r#"
            ledger-api.port = 7501
            include "optional-missing.conf"
            storage = ${_shared.storage}
            "#,
        )
        .unwrap();
        std::fs::write(
            dir.join("main.conf"),
            r#"
            include required(file("sub/shared"))
            canton.participants.p1 {
              include required("sub/nested.conf")
            }
            "#,
        )
        .unwrap();

        let conf = parse_file(&dir.join("main.conf"), &none).unwrap();
        assert_eq!(
            conf.get("canton.participants.p1.http-ledger-api.port")
                .unwrap()
                .as_u16(),
            Some(7575)
        );
        assert_eq!(
            conf.get("canton.participants.p1.ledger-api.port")
                .unwrap()
                .as_u16(),
            Some(7501)
        );
        assert_eq!(
            conf.get("canton.participants.p1.storage.type")
                .unwrap()
                .text()
                .unwrap(),
            "postgres"
        );

        // Negative control 1: missing required include fails loudly
        std::fs::write(
            dir.join("missing-req.conf"),
            "include required(\"does-not-exist.conf\")\n",
        )
        .unwrap();
        assert!(parse_file(&dir.join("missing-req.conf"), &none).is_err());

        // Negative control 2: include cycle fails loudly
        std::fs::write(dir.join("a.conf"), "include required(\"b.conf\")\n").unwrap();
        std::fs::write(dir.join("b.conf"), "include required(\"a.conf\")\n").unwrap();
        let err = parse_file(&dir.join("a.conf"), &none).unwrap_err();
        assert!(err.contains("cycle"), "{err}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn what_it_does_not_read_is_an_error() {
        assert!(parse("include \"other.conf\"", &none).is_err());
        assert!(parse("a = ${NOPE}", &none).is_err());
        assert!(parse("a { b = 1", &none).is_err());
        assert!(parse("a = 1\na += 2", &none).is_err());
        assert!(parse(
            "a = \"x\"\ninclude url(\"https://example.com/a.conf\")",
            &none
        )
        .is_err());
    }
}
