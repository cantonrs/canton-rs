//! A log line in the form of a Canton 3.7.2 node's log (`--log-encoder plain|json`), for the lines the daemon says about its nodes (U-47).
//!
//! [CANTON-NOTE: SEMANTICS] Measured on the hub's Canton (`docker logs`, and a JSON line the user's participant wrote):
//! - **plain**: `2026-11-17 12:19:17,420 [canton-env-ec-148] INFO  c.d.c.s.s.b.b.c.m.c.i.IssSegmentModule:sequencer=sequencer1/psid=hub-sync::12204e8bfbed::37-0
//!   tid:fa5f03e59e6126a715c1a39da6f5a159 - message`: the time in milliseconds with a comma, the thread in brackets, the level padded to five letters, the logger name with
//!   `:` and the node's context (`participant=p1`, `sequencer=s1/psid=...`), the trace id after `tid:` (left out without one), ` - ` and the message;
//! - **json**: one object per line with `@timestamp` (`2026-11-17T12:14:40.202Z`), `message`, `logger_name` (the same name and context), `thread_name`, `level`
//!   and, with a trace, `span-id`, `span-parent-id`, `trace-id` and `span-name`.
//!
//! The logger names are strings here (a Rust program has no Java classes); the messages are the program's own words, not Canton's.
use serde_json::json;

/// How a line is written: `text` is the program's own plain output (no time, no thread), `plain` and `json` are Canton's two encoders.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum LogEncoder {
    Text,
    Plain,
    Json,
}

/// The trace a line belongs to (the parts of a W3C `traceparent` and the span's name).
pub struct Trace<'a> {
    pub trace_id: &'a str,
    pub span_id: &'a str,
    pub parent_span_id: &'a str,
    pub span_name: &'a str,
}

pub struct Line<'a> {
    pub micros: i64,
    pub thread: &'a str,
    pub level: &'a str,
    pub logger: &'a str,
    /// The node's context after the logger name (`participant=p1`), empty for none.
    pub context: &'a str,
    pub trace: Option<Trace<'a>>,
    pub message: &'a str,
}

/// `2026-11-17 12:19:17,420` and `2026-11-17T12:19:17.420Z` of a time in microseconds since the epoch.
fn times(micros: i64) -> (String, String) {
    let (secs, millis) = (
        micros.div_euclid(1_000_000),
        micros.rem_euclid(1_000_000) / 1000,
    );
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Howard Hinnant's civil_from_days
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let (h, m, s) = (rem / 3600, rem % 3600 / 60, rem % 60);
    (
        format!("{year:04}-{month:02}-{day:02} {h:02}:{m:02}:{s:02},{millis:03}"),
        format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}.{millis:03}Z"),
    )
}

impl Line<'_> {
    pub fn render(&self, encoder: LogEncoder) -> String {
        let (plain_time, iso_time) = times(self.micros);
        let logger = if self.context.is_empty() {
            self.logger.to_string()
        } else {
            format!("{}:{}", self.logger, self.context)
        };
        match encoder {
            LogEncoder::Text => self.message.to_string(),
            LogEncoder::Plain => {
                let tid = self
                    .trace
                    .as_ref()
                    .map(|t| format!(" tid:{}", t.trace_id))
                    .unwrap_or_default();
                format!(
                    "{plain_time} [{}] {:<5} {logger}{tid} - {}",
                    self.thread, self.level, self.message
                )
            }
            LogEncoder::Json => {
                let mut line = json!({
                    "@timestamp": iso_time,
                    "message": self.message,
                    "logger_name": logger,
                    "thread_name": self.thread,
                    "level": self.level,
                });
                if let Some(t) = &self.trace {
                    line["span-id"] = json!(t.span_id);
                    line["span-parent-id"] = json!(t.parent_span_id);
                    line["trace-id"] = json!(t.trace_id);
                    line["span-name"] = json!(t.span_name);
                }
                line.to_string()
            }
        }
    }
}

/// Prints a line of the daemon in `encoder`.
pub fn emit(encoder: LogEncoder, level: &str, logger: &str, context: &str, message: &str) {
    // the program's own lines start with a space; Canton's encoders write the message as it is
    let message = if encoder == LogEncoder::Text {
        message
    } else {
        message.trim_start()
    };
    let micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_micros() as i64);
    crate::diag::diag_println!(
        "{}",
        Line {
            micros,
            thread: "main",
            level,
            logger,
            context,
            trace: None,
            message,
        }
        .render(encoder)
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-11-17 12:19:17.420 UTC in microseconds.
    const AT: i64 = 1_794_917_957_420_000;

    #[test]
    fn a_plain_line_has_canton_s_shape() {
        let line = Line {
            micros: AT,
            thread: "canton-env-ec-148",
            level: "INFO",
            logger: "c.d.c.s.s.b.b.c.m.c.i.IssSegmentModule",
            context: "sequencer=sequencer1/psid=hub-sync::12204e8bfbed::37-0",
            trace: Some(Trace {
                trace_id: "fa5f03e59e6126a715c1a39da6f5a159",
                span_id: "9a1287fc43f4ca91",
                parent_span_id: "c6a215e50d4c4f99",
                span_name: "x",
            }),
            message: "block timeout reached",
        };
        assert_eq!(
            line.render(LogEncoder::Plain),
            "2026-11-17 12:19:17,420 [canton-env-ec-148] INFO  c.d.c.s.s.b.b.c.m.c.i.IssSegmentModule:sequencer=sequencer1/psid=hub-sync::12204e8bfbed::37-0 tid:fa5f03e59e6126a715c1a39da6f5a159 - block timeout reached"
        );
    }

    #[test]
    fn a_json_line_has_the_fields_of_the_participants_log() {
        let line = Line {
            micros: AT,
            thread: "canton-env-ec-244",
            level: "DEBUG",
            logger: "c.d.c.l.a.ApiRequestLogger",
            context: "participant=app-provider",
            trace: Some(Trace {
                trace_id: "764e17a8a9d80968ecbae70f3f72cd3e",
                span_id: "9a1287fc43f4ca91",
                parent_span_id: "c6a215e50d4c4f99",
                span_name: "com.daml.ledger.api.v2.UpdateService/GetUpdates",
            }),
            message: "Request com.daml.ledger.api.v2.UpdateService/GetUpdates by grpc:/172.24.0.4:59484: sending response ",
        };
        let json: serde_json::Value = serde_json::from_str(&line.render(LogEncoder::Json)).unwrap();
        assert_eq!(json["@timestamp"], "2026-11-17T12:19:17.420Z");
        assert_eq!(
            json["logger_name"],
            "c.d.c.l.a.ApiRequestLogger:participant=app-provider"
        );
        assert_eq!(json["level"], "DEBUG");
        assert_eq!(json["thread_name"], "canton-env-ec-244");
        assert_eq!(json["trace-id"], "764e17a8a9d80968ecbae70f3f72cd3e");
        assert_eq!(json["span-parent-id"], "c6a215e50d4c4f99");
        assert_eq!(
            json["span-name"],
            "com.daml.ledger.api.v2.UpdateService/GetUpdates"
        );
        // exactly the keys the participant's line has
        assert_eq!(json.as_object().unwrap().len(), 9);
    }

    #[test]
    fn a_line_without_a_trace_has_no_trace_fields_and_text_is_the_message() {
        let line = Line {
            micros: AT,
            thread: "main",
            level: "WARN",
            logger: "canton-rs",
            context: "",
            trace: None,
            message: "hello",
        };
        assert_eq!(
            line.render(LogEncoder::Plain),
            "2026-11-17 12:19:17,420 [main] WARN  canton-rs - hello"
        );
        assert!(line
            .render(LogEncoder::Json)
            .contains("\"logger_name\":\"canton-rs\""));
        assert!(!line.render(LogEncoder::Json).contains("trace-id"));
        assert_eq!(line.render(LogEncoder::Text), "hello");
    }
}
