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
    "usage:\n\
      nexus browse <site[/path]> [--server HOST:PORT] [--pin SITE_ID]\n\
      nexus sync --server HOST:PORT --site NAME --dir PATH [--pin SITE_ID]\n\
      nexus cache-gc [--dir PATH]\n\
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

fn sync_usage() -> &'static str {
    "usage: nexus sync --server HOST:PORT --site NAME --dir PATH [--pin SITE_ID]"
}

#[derive(Debug, PartialEq, Eq)]
struct SyncArgs {
    server: String,
    site: String,
    dir: std::path::PathBuf,
    pin: Option<String>,
}

fn parse_sync_args(args: &[String]) -> Result<SyncArgs, i32> {
    let mut server = None;
    let mut site = None;
    let mut dir = None;
    let mut pin = None;
    let mut it = args.iter().peekable();
    while let Some(a) = it.next() {
        match a.as_str() {
            "sync" => {}
            "--server" | "--site" | "--dir" | "--pin" => {
                let v = match it.next() {
                    Some(v) => v.clone(),
                    None => {
                        eprintln!("{}", sync_usage());
                        return Err(2);
                    }
                };
                match a.as_str() {
                    "--server" => server = Some(v),
                    "--site" => site = Some(v),
                    "--dir" => dir = Some(v.into()),
                    _ => pin = Some(v),
                }
            }
            s if s.starts_with('-') => {
                eprintln!("unknown arg: {s}\n{}", sync_usage());
                return Err(2);
            }
            s => {
                eprintln!("unexpected arg: {s}\n{}", sync_usage());
                return Err(2);
            }
        }
    }
    match (server, site, dir) {
        (Some(server), Some(site), Some(dir)) => Ok(SyncArgs {
            server,
            site,
            dir,
            pin,
        }),
        _ => {
            eprintln!("{}", sync_usage());
            Err(2)
        }
    }
}

/// Mirror a whole site to a directory. Exit code is the process contract:
/// 0 = all listed pages synced (and verified, with --pin), 1 = fetch /
/// verify / write failure, 2 = bad arguments.
fn cmd_sync(args: &[String]) -> i32 {
    let parsed = match parse_sync_args(args) {
        Ok(a) => a,
        Err(code) => return code,
    };
    match nexus_browser::sync_site(
        &parsed.server,
        &parsed.site,
        parsed.pin.as_deref(),
        &parsed.dir,
    ) {
        Ok(report) => {
            println!(
                "synced {} page(s) ({} verified, {} skipped) from {} to {}",
                report.pages,
                report.verified,
                report.skipped,
                parsed.site,
                parsed.dir.display()
            );
            0
        }
        Err(e) => {
            eprintln!("nexus sync: {e}");
            1
        }
    }
}

/// Delete orphaned cache blobs and interrupted-write leftovers.
/// Exit 0 with a report line; never fails on a missing/empty cache.
fn cmd_cache_gc(args: &[String]) -> i32 {
    let mut dir: Option<std::path::PathBuf> = None;
    let mut it = args.iter().peekable();
    while let Some(a) = it.next() {
        match a.as_str() {
            "cache-gc" => {}
            "--dir" => match it.next() {
                Some(v) => dir = Some(v.into()),
                None => {
                    eprintln!("usage: nexus cache-gc [--dir PATH]");
                    return 2;
                }
            },
            s if s.starts_with('-') => {
                eprintln!("unknown arg: {s}\nusage: nexus cache-gc [--dir PATH]");
                return 2;
            }
            s => {
                eprintln!("unexpected arg: {s}\nusage: nexus cache-gc [--dir PATH]");
                return 2;
            }
        }
    }
    let cache = match dir {
        Some(d) => nexus_browser::OfflineCache::new(d),
        None => nexus_browser::OfflineCache::open_default(),
    };
    let report = cache.gc();
    println!(
        "collected {} file(s), freed {} byte(s)",
        report.files_removed, report.bytes_freed
    );
    0
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
    if args.first().is_some_and(|a| a == "sync") {
        std::process::exit(cmd_sync(&args));
    }
    if args.first().is_some_and(|a| a == "cache-gc") {
        std::process::exit(cmd_cache_gc(&args));
    }
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

    #[test]
    fn parses_sync_args() {
        let a = parse_sync_args(&[
            "sync".into(),
            "--server".into(),
            "10.0.0.1:1".into(),
            "--site".into(),
            "example".into(),
            "--dir".into(),
            "/tmp/x".into(),
        ])
        .unwrap();
        assert_eq!(a.server, "10.0.0.1:1");
        assert_eq!(a.site, "example");
        assert_eq!(a.pin, None);
        let a = parse_sync_args(&[
            "sync".into(),
            "--server".into(),
            "10.0.0.1:1".into(),
            "--site".into(),
            "example".into(),
            "--dir".into(),
            "/tmp/x".into(),
            "--pin".into(),
            "abc".into(),
        ])
        .unwrap();
        assert_eq!(a.pin, Some("abc".to_string()));
        assert_eq!(
            parse_sync_args(&["sync".into(), "--site".into(), "e".into()]),
            Err(2)
        );
        assert_eq!(parse_sync_args(&["sync".into(), "--bogus".into()]), Err(2));
    }
}
