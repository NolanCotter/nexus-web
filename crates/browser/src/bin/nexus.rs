//! Unified `nexus` CLI browser (Milestone F).
//!
//! `nexus browse <site[/path]> [--server HOST:PORT]` renders a page via
//! nexus-renderer, then drops into an interactive session with back/forward
//! navigation, reload, and history. The wire protocol (NXP/0.1) is unchanged;
//! this binary shares the resolve->fetch path of `nexus-browser`.

use nexus_browser::ClientSession;
use std::io::{self, BufRead, Write};

const DEFAULT_SERVER: &str = "127.0.0.1:7843";

fn usage() -> &'static str {
    "usage: nexus browse <site[/path]> [--server HOST:PORT] [--pin SITE_ID]\n\
     \n\
     commands at the prompt:\n\
       b | back       go back in history\n\
       f | forward    go forward in history\n\
       h | history    list history (=> marks current)\n\
       g <target>     goto <site[/path]> (or type it bare)\n\
       r | reload     refetch the current page\n\
       ? | help       this text\n\
       q | quit       exit"
}

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Back,
    Forward,
    History,
    Open(String),
    Reload,
    Help,
    Quit,
    Noop,
}

fn parse_command(line: &str) -> Command {
    let line = line.trim();
    let (word, rest) = match line.split_once(' ') {
        Some((w, r)) => (w, r.trim()),
        None => (line, ""),
    };
    match word {
        "b" | "back" => Command::Back,
        "f" | "forward" => Command::Forward,
        "h" | "history" => Command::History,
        "g" | "goto" => Command::Open(rest.to_string()),
        "r" | "reload" => Command::Reload,
        "q" | "quit" | "exit" => Command::Quit,
        "?" | "help" => Command::Help,
        "" => Command::Noop,
        _ => Command::Open(line.to_string()),
    }
}

/// Err(code) once the process should exit (help/version printed, or bad args).
fn parse_args(args: &[String]) -> Result<(String, Option<String>, Option<String>), i32> {
    let mut server = DEFAULT_SERVER.to_string();
    let mut target = None;
    let mut pin: Option<String> = None;
    let mut it = args.iter().peekable();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => {
                println!("{}", usage());
                return Err(0);
            }
            "--version" => {
                println!("nexus {}", env!("CARGO_PKG_VERSION"));
                return Err(0);
            }
            "--server" => {
                server = match it.next() {
                    Some(v) => v.clone(),
                    None => {
                        eprintln!("{}", usage());
                        return Err(2);
                    }
                };
            }
            "--pin" => {
                pin = Some(match it.next() {
                    Some(v) => v.clone(),
                    None => {
                        eprintln!("{}", usage());
                        return Err(2);
                    }
                });
            }
            "browse" => {}
            s if s.starts_with('-') => {
                eprintln!("unknown arg: {s}\n{}", usage());
                return Err(2);
            }
            s => target = Some(s.to_string()),
        }
    }
    Ok((server, target, pin))
}

fn render(session: &ClientSession) {
    if let Some(v) = session.history.current() {
        println!(
            "[{} of {}] @{} /{}",
            session.history.position() + 1,
            session.history.len(),
            v.site,
            v.path
        );
    }
    print!("{}", session.render_current());
    let _ = io::stdout().flush();
}

fn print_history(session: &ClientSession) {
    let pos = session.history.position();
    for (i, v) in session.history.entries().iter().enumerate() {
        let marker = if i == pos { "=>" } else { "" };
        println!(
            "{marker:>2} {}. @{} /{}   {}",
            i + 1,
            v.site,
            v.path,
            v.page.metadata.title
        );
    }
}

fn run_nav(session: &mut ClientSession, cmd: Command) {
    let res = match cmd {
        Command::Back => session.back(),
        Command::Forward => session.forward(),
        Command::Reload => session.reload(),
        Command::Open(t) => session.open(&t),
        _ => return,
    };
    match res {
        Ok(()) => render(session),
        Err(e) => eprintln!("nexus: {e}"),
    }
}

fn interactive(session: &mut ClientSession) {
    let stdin = io::stdin();
    let mut input = stdin.lock();
    loop {
        print!("nexus> ");
        let _ = io::stdout().flush();
        let mut line = String::new();
        match input.read_line(&mut line) {
            Ok(0) | Err(_) => return, // EOF (Ctrl-D) or read error
            Ok(_) => {}
        }
        match parse_command(&line) {
            Command::Quit => return,
            Command::Noop => {}
            Command::Help => println!("{}", usage()),
            Command::History => print_history(session),
            cmd => run_nav(session, cmd),
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (server, target, pin) = match parse_args(&args) {
        Ok(t) => t,
        Err(code) => std::process::exit(code),
    };
    let Some(target) = target else {
        eprintln!("{}", usage());
        std::process::exit(2);
    };

    let mut session = ClientSession::new(server).with_pin(pin);
    if let Err(e) = session.open(&target) {
        eprintln!("nexus: {target}: {e}");
        std::process::exit(1);
    }
    render(&session);
    interactive(&mut session);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nav_commands() {
        assert_eq!(parse_command("b"), Command::Back);
        assert_eq!(parse_command("back"), Command::Back);
        assert_eq!(parse_command("f"), Command::Forward);
        assert_eq!(parse_command("h"), Command::History);
        assert_eq!(parse_command("r"), Command::Reload);
        assert_eq!(parse_command("q"), Command::Quit);
        assert_eq!(parse_command("exit"), Command::Quit);
        assert_eq!(parse_command("?"), Command::Help);
        assert_eq!(parse_command(""), Command::Noop);
    }

    #[test]
    fn parses_goto_and_bare_targets() {
        assert_eq!(
            parse_command("g example/about"),
            Command::Open("example/about".into())
        );
        assert_eq!(
            parse_command("goto   example  "),
            Command::Open("example".into())
        );
        assert_eq!(
            parse_command("example/blog/1"),
            Command::Open("example/blog/1".into())
        );
    }

    #[test]
    fn parses_cli_args() {
        assert_eq!(
            parse_args(&[
                "browse".into(),
                "example/home".into(),
                "--server".into(),
                "127.0.0.1:9".into()
            ])
            .unwrap(),
            (
                "127.0.0.1:9".to_string(),
                Some("example/home".to_string()),
                None
            )
        );
        assert_eq!(
            parse_args(&["example".into()]).unwrap(),
            (
                DEFAULT_SERVER.to_string(),
                Some("example".to_string()),
                None
            )
        );
        assert_eq!(
            parse_args(&[
                "browse".into(),
                "example".into(),
                "--pin".into(),
                "abc123".into()
            ])
            .unwrap(),
            (
                DEFAULT_SERVER.to_string(),
                Some("example".to_string()),
                Some("abc123".to_string())
            )
        );
        assert_eq!(parse_args(&["--nope".into()]), Err(2));
        assert_eq!(parse_args(&["--help".into()]), Err(0));
        assert_eq!(parse_args(&["browse".into(), "--pin".into()]), Err(2));
    }
}
