//! Pure-Rust terminal backend, RAII raw-mode guard, and `libc::poll` keyboard reader.
//!
//! [CANTON-NOTE: INVARIANT] Uses `ratatui_core` + `crossterm` (`libc` mode without
//! `events`/`signal-hook`) and non-blocking `libc::poll` raw STDIN reading so Gate G11
//! introduces zero C compilation dependencies.

use std::io::{self, Write};

use crossterm::cursor::{Hide, MoveTo, Show};
use crossterm::style::{
    Attribute as CtAttr, Color as CtColor, Print, SetAttribute, SetBackgroundColor,
    SetForegroundColor,
};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, Clear as CtClear, ClearType as CtClearType,
    EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::{execute, queue};
use ratatui_core::backend::{Backend, ClearType, WindowSize};
use ratatui_core::buffer::Cell;
use ratatui_core::layout::{Position, Size};
use ratatui_core::style::{Color, Modifier};

/// Pure-Rust `CrosstermBackend` bridging `ratatui_core` without `ratatui-termwiz`/`termina`.
pub struct CrosstermBackend<W: Write> {
    writer: W,
}

impl<W: Write> CrosstermBackend<W> {
    /// Wraps an output writer (typically `std::io::stdout()` or a `Vec<u8>` buffer in tests).
    pub fn new(writer: W) -> Self {
        Self { writer }
    }
}

impl<W: Write> Backend for CrosstermBackend<W> {
    type Error = io::Error;

    fn draw<'a, I>(&mut self, content: I) -> io::Result<()>
    where
        I: Iterator<Item = (u16, u16, &'a Cell)>,
    {
        let mut fg = Color::Reset;
        let mut bg = Color::Reset;
        let mut last_pos: Option<Position> = None;
        let mut bold = false;
        let mut dim = false;
        let mut reversed = false;
        let mut underlined = false;

        for (x, y, cell) in content {
            let sym = cell.symbol();
            // [CANTON-NOTE: DEFENSIVE] `ratatui_core` represents the trailing half of a 2-column
            // glyph as an empty symbol; skip emitting it and force explicit `MoveTo` afterward.
            if sym.is_empty() {
                last_pos = None;
                continue;
            }

            if !matches!(last_pos, Some(p) if x == p.x + 1 && y == p.y) {
                queue!(self.writer, MoveTo(x, y))?;
            }

            let want_bold = cell.modifier.contains(Modifier::BOLD);
            let want_dim = cell.modifier.contains(Modifier::DIM);
            let want_rev = cell.modifier.contains(Modifier::REVERSED);
            let want_ul = cell.modifier.contains(Modifier::UNDERLINED);

            if want_bold != bold || want_dim != dim {
                queue!(self.writer, SetAttribute(CtAttr::NormalIntensity))?;
                if want_bold {
                    queue!(self.writer, SetAttribute(CtAttr::Bold))?;
                }
                if want_dim {
                    queue!(self.writer, SetAttribute(CtAttr::Dim))?;
                }
                bold = want_bold;
                dim = want_dim;
            }
            if want_rev != reversed {
                queue!(
                    self.writer,
                    SetAttribute(if want_rev {
                        CtAttr::Reverse
                    } else {
                        CtAttr::NoReverse
                    })
                )?;
                reversed = want_rev;
            }
            if want_ul != underlined {
                queue!(
                    self.writer,
                    SetAttribute(if want_ul {
                        CtAttr::Underlined
                    } else {
                        CtAttr::NoUnderline
                    })
                )?;
                underlined = want_ul;
            }
            if cell.fg != fg {
                queue!(self.writer, SetForegroundColor(to_ct_color(cell.fg)))?;
                fg = cell.fg;
            }
            if cell.bg != bg {
                queue!(self.writer, SetBackgroundColor(to_ct_color(cell.bg)))?;
                bg = cell.bg;
            }
            queue!(self.writer, Print(sym))?;

            // [CANTON-NOTE: DEFENSIVE] Ambiguous-width Unicode glyphs (`▶`, `▸`, `●`, `■`, `▲`,
            // `↻`, `✖`, box borders, sparklines) can occupy 1 or 2 columns depending on macOS CJK
            // terminal fonts. Clearing `last_pos` forces an explicit `MoveTo` for the next cell so
            // table columns stay pixel-aligned across all terminals.
            last_pos = if sym.is_ascii() {
                Some(Position { x, y })
            } else {
                None
            };
        }
        queue!(
            self.writer,
            SetForegroundColor(CtColor::Reset),
            SetBackgroundColor(CtColor::Reset),
            SetAttribute(CtAttr::Reset),
        )
    }

    fn hide_cursor(&mut self) -> io::Result<()> {
        execute!(self.writer, Hide)
    }

    fn show_cursor(&mut self) -> io::Result<()> {
        execute!(self.writer, Show)
    }

    fn get_cursor_position(&mut self) -> io::Result<Position> {
        Ok(Position { x: 0, y: 0 })
    }

    fn set_cursor_position<P: Into<Position>>(&mut self, position: P) -> io::Result<()> {
        let Position { x, y } = position.into();
        execute!(self.writer, MoveTo(x, y))
    }

    fn clear(&mut self) -> io::Result<()> {
        execute!(self.writer, CtClear(CtClearType::All))
    }

    fn clear_region(&mut self, clear_type: ClearType) -> io::Result<()> {
        let ct = match clear_type {
            ClearType::All => CtClearType::All,
            ClearType::AfterCursor => CtClearType::FromCursorDown,
            ClearType::BeforeCursor => CtClearType::FromCursorUp,
            ClearType::CurrentLine => CtClearType::CurrentLine,
            ClearType::UntilNewLine => CtClearType::UntilNewLine,
        };
        execute!(self.writer, CtClear(ct))
    }

    fn size(&self) -> io::Result<Size> {
        let (cols, rows) = crossterm::terminal::size()?;
        Ok(Size::new(cols, rows))
    }

    fn window_size(&mut self) -> io::Result<WindowSize> {
        let ws = crossterm::terminal::window_size()?;
        Ok(WindowSize {
            columns_rows: Size::new(ws.columns, ws.rows),
            pixels: Size::new(ws.width, ws.height),
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

/// Maps `ratatui_core` colors cleanly to `crossterm` terminal colors.
pub fn to_ct_color(c: Color) -> CtColor {
    match c {
        Color::Reset => CtColor::Reset,
        Color::Black => CtColor::Black,
        Color::Red => CtColor::DarkRed,
        Color::Green => CtColor::DarkGreen,
        Color::Yellow => CtColor::DarkYellow,
        Color::Blue => CtColor::DarkBlue,
        Color::Magenta => CtColor::DarkMagenta,
        Color::Cyan => CtColor::DarkCyan,
        Color::Gray => CtColor::Grey,
        Color::DarkGray => CtColor::DarkGrey,
        Color::LightRed => CtColor::Red,
        Color::LightGreen => CtColor::Green,
        Color::LightYellow => CtColor::Yellow,
        Color::LightBlue => CtColor::Blue,
        Color::LightMagenta => CtColor::Magenta,
        Color::LightCyan => CtColor::Cyan,
        Color::White => CtColor::White,
        Color::Rgb(r, g, b) => CtColor::Rgb { r, g, b },
        Color::Indexed(i) => CtColor::AnsiValue(i),
    }
}

/// RAII guard entering raw alternate-screen mode and restoring the user shell on drop.
pub struct TerminalGuard;

impl TerminalGuard {
    /// Enters raw mode, alternate screen buffer, and hides the cursor.
    pub fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen, Hide)?;
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = execute!(io::stdout(), Show, LeaveAlternateScreen);
        let _ = disable_raw_mode();
    }
}

/// Normalized keyboard event decoded from raw STDIN escape sequences.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Key {
    Up,
    Down,
    Left,
    Right,
    PageUp,
    PageDown,
    Home,
    End,
    Tab,
    BackTab,
    Enter,
    Esc,
    Backspace,
    CtrlC,
    Char(char),
}

/// Non-blocking single-key reader over raw STDIN via `libc::poll` (zero `signal-hook`).
pub fn read_key_timeout(timeout_ms: i32) -> Option<Key> {
    let mut pfd = libc::pollfd {
        fd: libc::STDIN_FILENO,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `pfd` is a valid stack `pollfd` describing `STDIN_FILENO` with `nfds = 1`.
    let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    if rc <= 0 || (pfd.revents & libc::POLLIN) == 0 {
        return None;
    }
    let mut buf = [0u8; 8];
    // SAFETY: Reading up to 8 raw bytes from ready `STDIN_FILENO` into stack buffer `buf`.
    let n = unsafe { libc::read(libc::STDIN_FILENO, buf.as_mut_ptr().cast(), buf.len()) };
    if n <= 0 {
        return None;
    }
    decode_key_bytes(&buf[..n as usize])
}

/// Decodes ANSI/VT escape byte sequences into `Key` variants.
pub fn decode_key_bytes(slice: &[u8]) -> Option<Key> {
    Some(match slice {
        [0x03, ..] => Key::CtrlC,
        [b'\r', ..] | [b'\n', ..] => Key::Enter,
        [b'\t', ..] => Key::Tab,
        [0x7f, ..] | [0x08, ..] => Key::Backspace,
        [0x1b] => Key::Esc,
        [0x1b, b'[', b'A', ..] | [0x1b, b'O', b'A', ..] => Key::Up,
        [0x1b, b'[', b'B', ..] | [0x1b, b'O', b'B', ..] => Key::Down,
        [0x1b, b'[', b'C', ..] | [0x1b, b'O', b'C', ..] => Key::Right,
        [0x1b, b'[', b'D', ..] | [0x1b, b'O', b'D', ..] => Key::Left,
        [0x1b, b'[', b'Z', ..] => Key::BackTab,
        [0x1b, b'[', b'5', b'~', ..] => Key::PageUp,
        [0x1b, b'[', b'6', b'~', ..] => Key::PageDown,
        [0x1b, b'[', b'H', ..] | [0x1b, b'O', b'H', ..] | [0x1b, b'[', b'1', b'~', ..] => Key::Home,
        [0x1b, b'[', b'F', ..] | [0x1b, b'O', b'F', ..] | [0x1b, b'[', b'4', b'~', ..] => Key::End,
        [b, ..] if (*b as char).is_ascii() => Key::Char(*b as char),
        _ => return None,
    })
}
