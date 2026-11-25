//! The console's expression language: values, tokens and the parser.

use std::collections::BTreeMap;

use serde_json::{json, Value as Json};

/// A console value.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Text(String),
    /// A `PartyId`, held whole (`alice::1220…` with all 68 hex digits of the namespace).
    Party(String),
    /// A `ParticipantId`, held as its unique identifier (`participant1::1220…`).
    Participant(String),
    Unit,
    Long(i64),
    Bool(bool),
    Seq(Vec<Value>),
    Object(BTreeMap<String, Value>),
    Some(Box<Value>),
    None,
    /// `_.field`, an argument of `map`.
    Lambda(String),
    /// A Ledger API `Command` (`ledger_api_utils.create`/`exercise`), as the JSON Ledger API takes it.
    Command(Json),
}

impl Value {
    /// A value as a Daml-LF JSON argument of a command (`Map("owner" -> alice)` becomes `{"owner": "alice::..."}`).
    pub(super) fn to_json(&self) -> Json {
        match self {
            Value::Text(t) | Value::Party(t) | Value::Participant(t) => Json::String(t.clone()),
            Value::Long(n) => Json::String(n.to_string()),
            Value::Bool(b) => Json::Bool(*b),
            Value::Seq(items) => Json::Array(items.iter().map(Value::to_json).collect()),
            Value::Object(fields) => Json::Object(
                fields
                    .iter()
                    .map(|(k, v)| (k.clone(), v.to_json()))
                    .collect(),
            ),
            Value::Some(v) => v.to_json(),
            Value::None => Json::Null,
            Value::Unit => json!({}),
            Value::Lambda(_) => Json::Null,
            Value::Command(c) => c.clone(),
        }
    }

    /// What `println` prints (Scala's `toString` for the values here).
    pub(super) fn show(&self) -> String {
        match self {
            Value::Text(t) => t.clone(),
            // [CANTON-NOTE: SEMANTICS] `UniqueIdentifier`'s pretty form: the namespace's fingerprint through `readableHash`, its first 12
            // characters and `...` (`ShowUtil.HashLength`; measured: `println(alice)` prints `alice::122002f19cae...`).
            Value::Party(p) => match p.split_once("::") {
                Some((hint, ns)) if ns.chars().count() > 12 => {
                    format!("{hint}::{}...", ns.chars().take(12).collect::<String>())
                }
                _ => p.clone(),
            },
            // [CANTON-NOTE: SEMANTICS] `ParticipantId`'s pretty form: its member code and the unique identifier (`PAR::participant1::…`)
            Value::Participant(p) => format!("PAR::{}", Value::Party(p.clone()).show()),
            Value::Unit => "()".into(),
            Value::Long(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Seq(items) => format!(
                "List({})",
                items.iter().map(Value::show).collect::<Vec<_>>().join(", ")
            ),
            Value::Some(v) => format!("Some({})", v.show()),
            Value::None => "None".into(),
            Value::Object(fields) => format!(
                "({})",
                fields
                    .iter()
                    .map(|(k, v)| format!("{k} = {}", v.show()))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Value::Lambda(f) => format!("_.{f}"),
            Value::Command(c) => format!("Command({c})"),
        }
    }

    /// One step on a value: a Scala collection method or a field.
    pub(super) fn step(self, name: &str, args: &[Value]) -> Result<Value, String> {
        match (self, name, args) {
            (Value::Seq(items), "size" | "length", []) => Ok(Value::Long(items.len() as i64)),
            (Value::Seq(items), "isEmpty", []) => Ok(Value::Bool(items.is_empty())),
            (Value::Seq(items), "head", []) => items
                .into_iter()
                .next()
                .ok_or_else(|| "head of empty list".to_string()),
            (Value::Seq(items), "map", [Value::Lambda(field)]) => items
                .into_iter()
                .map(|v| v.step(field, &[]))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Seq),
            (Value::Seq(mut items), "sorted", []) => {
                items.sort_by_key(|v| v.show());
                Ok(Value::Seq(items))
            }
            (Value::Seq(items), "contains", [x]) => Ok(Value::Bool(items.contains(x))),
            (Value::Seq(items), "mkString", [Value::Text(sep)]) => Ok(Value::Text(
                items.iter().map(Value::show).collect::<Vec<_>>().join(sep),
            )),
            (Value::Text(t), "length", []) => Ok(Value::Long(t.chars().count() as i64)),
            (Value::Text(t), "startsWith", [Value::Text(p)]) => {
                Ok(Value::Bool(t.starts_with(p.as_str())))
            }
            (Value::Party(p), "toProtoPrimitive", []) => Ok(Value::Text(p)),
            (v, "toString", []) => Ok(Value::Text(v.show())),
            (Value::Object(mut fields), field, []) => fields
                .remove(field)
                .ok_or_else(|| format!("value {field} is not a member")),
            (v, name, _) => Err(format!("value {name} is not a member of {}", v.show())),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(super) enum Token {
    /// `->`
    Arrow,
    Ident(String),
    Text(String),
    Int(i64),
    Sym(char),
}

pub(super) fn tokenize(line: &str) -> Result<Vec<Token>, String> {
    let chars: Vec<char> = line.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
        } else if c == '"' {
            let mut text = String::new();
            i += 1;
            while i < chars.len() && chars[i] != '"' {
                if chars[i] == '\\' && i + 1 < chars.len() {
                    i += 1;
                    text.push(match chars[i] {
                        'n' => '\n',
                        't' => '\t',
                        other => other,
                    });
                } else {
                    text.push(chars[i]);
                }
                i += 1;
            }
            if i == chars.len() {
                return Err("a string is not closed".into());
            }
            i += 1;
            out.push(Token::Text(text));
        } else if c.is_ascii_digit() {
            let start = i;
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            let text: String = chars[start..i].iter().collect();
            out.push(Token::Int(
                text.parse().map_err(|_| format!("bad number {text}"))?,
            ));
        } else if c.is_alphabetic() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            out.push(Token::Ident(chars[start..i].iter().collect()));
        } else if c == '-' && chars.get(i + 1) == Some(&'>') {
            out.push(Token::Arrow);
            i += 2;
        } else if "().,=".contains(c) {
            out.push(Token::Sym(c));
            i += 1;
        } else {
            return Err(format!("unexpected character {c:?}"));
        }
    }
    Ok(out)
}

#[derive(Debug)]
pub(super) struct Step {
    pub(super) name: String,
    /// `None` for a field or a call without parentheses; `Some` for a call.
    pub(super) args: Option<Vec<Arg>>,
}

/// An argument of a call, by position or by parameter name (`id = "carol"`).
#[derive(Debug)]
pub(super) struct Arg {
    pub(super) name: Option<String>,
    pub(super) expr: Expr,
}

/// The arguments a command was called with.
#[derive(Default)]
pub(super) struct CallArgs {
    pub(super) positional: Vec<Value>,
    pub(super) named: BTreeMap<String, Value>,
}

impl CallArgs {
    /// The argument for the parameter at `index` called `name`: named, or by position.
    pub(super) fn get(&self, index: usize, name: &str) -> Option<&Value> {
        self.named.get(name).or_else(|| self.positional.get(index))
    }
}

#[derive(Debug)]
pub(super) enum Expr {
    Lit(Value),
    /// `Set(...)`, `Seq(...)`, `List(...)`, `Some(x)`
    Collection(String, Vec<Expr>),
    /// `_.field`
    Lambda(String),
    Path {
        root: String,
        steps: Vec<Step>,
    },
}

pub(super) struct Parser {
    pub(super) tokens: Vec<Token>,
    pub(super) at: usize,
}

impl Parser {
    pub(super) fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.at)
    }

    pub(super) fn eat_ident(&mut self, word: &str) -> bool {
        if self.peek() == Some(&Token::Ident(word.into())) {
            self.at += 1;
            true
        } else {
            false
        }
    }

    pub(super) fn ident(&mut self) -> Result<String, String> {
        match self.tokens.get(self.at) {
            Some(Token::Ident(name)) => {
                self.at += 1;
                Ok(name.clone())
            }
            other => Err(format!("a name expected, got {other:?}")),
        }
    }

    pub(super) fn expect(&mut self, token: &Token) -> Result<(), String> {
        if self.peek() == Some(token) {
            self.at += 1;
            Ok(())
        } else {
            Err(format!("{token:?} expected, got {:?}", self.peek()))
        }
    }

    pub(super) fn end(&self) -> Result<(), String> {
        match self.peek() {
            None => Ok(()),
            Some(t) => Err(format!("unexpected {t:?}")),
        }
    }

    pub(super) fn expr(&mut self) -> Result<Expr, String> {
        let root = match self.tokens.get(self.at).cloned() {
            Some(Token::Text(t)) => {
                self.at += 1;
                return Ok(Expr::Lit(Value::Text(t)));
            }
            Some(Token::Int(n)) => {
                self.at += 1;
                return Ok(Expr::Lit(Value::Long(n)));
            }
            Some(Token::Ident(word)) if word == "true" || word == "false" => {
                self.at += 1;
                return Ok(Expr::Lit(Value::Bool(word == "true")));
            }
            Some(Token::Ident(word)) if word == "None" => {
                self.at += 1;
                return Ok(Expr::Lit(Value::None));
            }
            Some(Token::Ident(word))
                if matches!(word.as_str(), "Set" | "Seq" | "List" | "Some" | "Map")
                    && self.tokens.get(self.at + 1) == Some(&Token::Sym('(')) =>
            {
                self.at += 2;
                let mut items = Vec::new();
                if self.peek() != Some(&Token::Sym(')')) {
                    loop {
                        items.push(self.expr()?);
                        if word == "Map" {
                            self.expect(&Token::Arrow)?;
                            items.push(self.expr()?);
                        }
                        if self.peek() == Some(&Token::Sym(',')) {
                            self.at += 1;
                        } else {
                            break;
                        }
                    }
                }
                self.expect(&Token::Sym(')'))?;
                return Ok(Expr::Collection(word, items));
            }
            Some(Token::Ident(word)) if word == "_" => {
                self.at += 1;
                self.expect(&Token::Sym('.'))?;
                return Ok(Expr::Lambda(self.ident()?));
            }
            Some(Token::Ident(word)) => {
                self.at += 1;
                word
            }
            other => return Err(format!("an expression expected, got {other:?}")),
        };
        let mut steps = Vec::new();
        while self.peek() == Some(&Token::Sym('.')) {
            self.at += 1;
            let name = self.ident()?;
            let args = if self.peek() == Some(&Token::Sym('(')) {
                self.at += 1;
                let mut args = Vec::new();
                if self.peek() != Some(&Token::Sym(')')) {
                    loop {
                        let name = match (self.tokens.get(self.at), self.tokens.get(self.at + 1)) {
                            (Some(Token::Ident(n)), Some(Token::Sym('='))) => {
                                let n = n.clone();
                                self.at += 2;
                                Some(n)
                            }
                            _ => None,
                        };
                        args.push(Arg {
                            name,
                            expr: self.expr()?,
                        });
                        if self.peek() == Some(&Token::Sym(',')) {
                            self.at += 1;
                        } else {
                            break;
                        }
                    }
                }
                self.expect(&Token::Sym(')'))?;
                Some(args)
            } else {
                None
            };
            steps.push(Step { name, args });
        }
        Ok(Expr::Path { root, steps })
    }
}
