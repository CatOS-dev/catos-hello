//! Internal pager for long human-readable reports.

use std::io::{self, BufRead, IsTerminal, Write};

pub fn present(text: &str) -> io::Result<()> {
    let stdin_is_tty = io::stdin().is_terminal();
    let stdout_is_tty = io::stdout().is_terminal();
    let rows = terminal_rows();
    if !should_page(stdin_is_tty, stdout_is_tty, text.lines().count(), rows) {
        let mut stdout = io::stdout().lock();
        stdout.write_all(text.as_bytes())?;
        return stdout.flush();
    }

    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    write_paginated(text, rows, &mut output, &mut input)
}

pub fn output_columns() -> usize {
    if !io::stdout().is_terminal() {
        return 78;
    }
    terminal_size().1
}

fn should_page(
    stdin_is_tty: bool,
    stdout_is_tty: bool,
    line_count: usize,
    terminal_rows: usize,
) -> bool {
    stdin_is_tty && stdout_is_tty && line_count > terminal_rows.max(1)
}

fn write_paginated<W: Write, R: BufRead>(
    text: &str,
    terminal_rows: usize,
    output: &mut W,
    input: &mut R,
) -> io::Result<()> {
    let lines = text.split_inclusive('\n').collect::<Vec<_>>();
    if lines.len() <= terminal_rows.max(1) {
        output.write_all(text.as_bytes())?;
        return output.flush();
    }

    let page_rows = terminal_rows.saturating_sub(2).max(1);
    let mut offset = 0;
    while offset < lines.len() {
        let end = (offset + page_rows).min(lines.len());
        for line in &lines[offset..end] {
            output.write_all(line.as_bytes())?;
        }
        offset = end;
        if offset == lines.len() {
            break;
        }

        output.write_all(b"-- More -- [Enter: next, q: quit] ")?;
        output.flush()?;
        let mut answer = String::new();
        input.read_line(&mut answer)?;
        output.write_all(b"\r\x1b[2K")?;
        if answer.trim().eq_ignore_ascii_case("q") {
            break;
        }
    }
    output.flush()
}

fn terminal_rows() -> usize {
    terminal_size().0
}

fn terminal_size() -> (usize, usize) {
    let mut size = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: TIOCGWINSZ only writes the supplied winsize structure for the
    // stdout file descriptor. Failure leaves the zero-initialised structure.
    let result = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut size) };
    if result == 0 {
        (
            if size.ws_row > 0 {
                usize::from(size.ws_row)
            } else {
                24
            },
            if size.ws_col > 0 {
                usize::from(size.ws_col)
            } else {
                78
            },
        )
    } else {
        (24, 78)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paging_requires_two_ttys_and_more_lines_than_the_terminal() {
        assert!(!should_page(false, true, 100, 24));
        assert!(!should_page(true, false, 100, 24));
        assert!(!should_page(true, true, 24, 24));
        assert!(should_page(true, true, 25, 24));
    }

    #[test]
    fn pager_advances_one_page_and_can_quit_without_printing_the_tail() {
        let text = "one\ntwo\nthree\nfour\nfive\nsix\nseven\n";
        let mut input = std::io::Cursor::new(b"\nq\n".to_vec());
        let mut output = Vec::new();
        write_paginated(text, 5, &mut output, &mut input).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("one\ntwo\nthree\n"));
        assert!(output.contains("four\nfive\nsix\n"));
        assert!(!output.contains("seven\n"));
        assert_eq!(output.matches("-- More --").count(), 2);
    }

    #[test]
    fn reports_that_fit_are_written_without_a_prompt() {
        let text = "one\ntwo\nthree\n";
        let mut input = std::io::Cursor::new(Vec::<u8>::new());
        let mut output = Vec::new();
        write_paginated(text, 3, &mut output, &mut input).unwrap();
        assert_eq!(String::from_utf8(output).unwrap(), text);
    }
}
