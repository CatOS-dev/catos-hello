//! Small line-oriented menus used by the public maintenance entry points.
//!
//! The menu deliberately uses plain terminal I/O rather than a full-screen
//! TUI. It remains usable in an initramfs console, over a serial terminal,
//! through `script`. Public menu entry points require both stdin and stdout to
//! be terminals; the generic helpers remain stream-based for unit testing.

use std::io::{self, BufRead, IsTerminal, Write};

pub fn is_interactive() -> bool {
    io::stdin().is_terminal() && io::stdout().is_terminal()
}

pub fn choose(title: &str, items: &[&str]) -> Result<Option<usize>, String> {
    choose_with_cancel_from_terminal(title, items, "Back")
}

pub fn choose_with_cancel_from_terminal(
    title: &str,
    items: &[&str],
    cancel_label: &str,
) -> Result<Option<usize>, String> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    choose_with_cancel(&mut input, &mut output, title, items, cancel_label)
}

#[cfg(test)]
pub fn choose_with<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    title: &str,
    items: &[&str],
) -> Result<Option<usize>, String> {
    choose_with_cancel(input, output, title, items, "Back")
}

pub fn choose_with_cancel<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    title: &str,
    items: &[&str],
    cancel_label: &str,
) -> Result<Option<usize>, String> {
    writeln!(output, "{title}").map_err(write_error)?;
    writeln!(output).map_err(write_error)?;
    for (index, item) in items.iter().enumerate() {
        writeln!(output, "  [{}] {item}", index + 1).map_err(write_error)?;
    }
    writeln!(output, "  [0] {cancel_label}").map_err(write_error)?;

    loop {
        write!(output, "\nSelect an action [0-{}]: ", items.len()).map_err(write_error)?;
        output.flush().map_err(write_error)?;

        let mut line = String::new();
        let read = input.read_line(&mut line).map_err(read_error)?;
        if read == 0 {
            writeln!(output).map_err(write_error)?;
            return Ok(None);
        }
        match line.trim().parse::<usize>() {
            Ok(0) => return Ok(None),
            Ok(value) if value <= items.len() => return Ok(Some(value - 1)),
            _ => {
                writeln!(output, "Please enter a number from 0 to {}.", items.len())
                    .map_err(write_error)?;
            }
        }
    }
}

pub fn prompt_optional(label: &str) -> Result<Option<String>, String> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    prompt_optional_with(&mut input, &mut output, label)
}

pub fn prompt_optional_with<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    label: &str,
) -> Result<Option<String>, String> {
    write!(output, "{label}: ").map_err(write_error)?;
    output.flush().map_err(write_error)?;
    let mut line = String::new();
    let read = input.read_line(&mut line).map_err(read_error)?;
    if read == 0 {
        writeln!(output).map_err(write_error)?;
        return Ok(None);
    }
    let value = line.trim();
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value.to_string()))
    }
}

pub fn prompt(label: &str) -> Result<Option<String>, String> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    prompt_with(&mut input, &mut output, label)
}

pub fn prompt_with<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    label: &str,
) -> Result<Option<String>, String> {
    write!(output, "{label} (blank to cancel): ").map_err(write_error)?;
    output.flush().map_err(write_error)?;
    let mut line = String::new();
    let read = input.read_line(&mut line).map_err(read_error)?;
    if read == 0 {
        writeln!(output).map_err(write_error)?;
        return Ok(None);
    }
    let value = line.trim();
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value.to_string()))
    }
}

pub fn confirm(prompt: &str) -> Result<bool, String> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    confirm_with(&mut input, &mut output, prompt)
}

pub fn confirm_with<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    prompt: &str,
) -> Result<bool, String> {
    loop {
        write!(output, "{prompt} [y/N]: ").map_err(write_error)?;
        output.flush().map_err(write_error)?;
        let mut line = String::new();
        let read = input.read_line(&mut line).map_err(read_error)?;
        if read == 0 {
            writeln!(output).map_err(write_error)?;
            return Ok(false);
        }
        match line.trim().to_ascii_lowercase().as_str() {
            "" | "n" | "no" => return Ok(false),
            "y" | "yes" => return Ok(true),
            _ => writeln!(output, "Please enter y or n.\n").map_err(write_error)?,
        }
    }
}

fn write_error(error: io::Error) -> String {
    format!("cannot write terminal output: {error}")
}

fn read_error(error: io::Error) -> String {
    format!("cannot read terminal input: {error}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn menu_reprompts_and_returns_the_selected_user_action() {
        let mut input = Cursor::new(b"wrong\n9\n2\n".to_vec());
        let mut output = Vec::new();
        let selected = choose_with(
            &mut input,
            &mut output,
            "CatOS System Tools",
            &["Check system health", "Open installed system"],
        )
        .unwrap();
        assert_eq!(selected, Some(1));
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("Please enter a number from 0 to 2."));
        assert!(output.contains("Open installed system"));
        assert_eq!(
            output.matches("CatOS System Tools").count(),
            1,
            "invalid input must not redraw the entire menu"
        );
    }

    #[test]
    fn menu_uses_the_callers_cancel_label() {
        let mut input = Cursor::new(b"0\n".to_vec());
        let mut output = Vec::new();
        assert_eq!(
            choose_with_cancel(
                &mut input,
                &mut output,
                "Top level",
                &["Action"],
                "Exit",
            )
            .unwrap(),
            None
        );
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("[0] Exit"));
        assert!(!output.contains("Exit / Back"));
    }

    #[test]
    fn eof_and_zero_both_cancel_without_an_error() {
        let mut eof = Cursor::new(Vec::<u8>::new());
        let mut output = Vec::new();
        assert_eq!(
            choose_with(&mut eof, &mut output, "Menu", &["Action"]).unwrap(),
            None
        );

        let mut zero = Cursor::new(b"0\n".to_vec());
        let mut output = Vec::new();
        assert_eq!(
            choose_with(&mut zero, &mut output, "Menu", &["Action"]).unwrap(),
            None
        );
    }

    #[test]
    fn optional_prompt_uses_blank_as_an_automatic_value() {
        let mut blank = Cursor::new(b"\n".to_vec());
        let mut output = Vec::new();
        assert_eq!(
            prompt_optional_with(&mut blank, &mut output, "Root subvolume").unwrap(),
            None
        );

        let mut value = Cursor::new(b"  /@  \n".to_vec());
        let mut output = Vec::new();
        assert_eq!(
            prompt_optional_with(&mut value, &mut output, "Root subvolume").unwrap(),
            Some("/@".into())
        );
        assert!(String::from_utf8(output).unwrap().contains("Root subvolume:"));
    }

    #[test]
    fn prompt_trims_input_and_blank_cancels() {
        let mut value = Cursor::new(b"  /dev/sda2  \n".to_vec());
        let mut output = Vec::new();
        assert_eq!(
            prompt_with(&mut value, &mut output, "Root device").unwrap(),
            Some("/dev/sda2".into())
        );

        let mut blank = Cursor::new(b"\n".to_vec());
        let mut output = Vec::new();
        assert_eq!(
            prompt_with(&mut blank, &mut output, "Root device").unwrap(),
            None
        );
    }
}
