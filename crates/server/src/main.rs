use std::net::TcpListener;
use std::path::PathBuf;

use nexus_server::{ServerConfig, SiteStore};

fn usage() -> &'static str {
    "usage: nexus-server [--port PORT] [--site NAME] [--dir PATH] [--max-connections N]"
}

fn main() {
    let mut port: u16 = 7843;
    let mut site = "example".to_string();
    let mut dir = PathBuf::from("sites/example");
    let mut config = ServerConfig::default();

    let mut args = std::env::args().skip(1).peekable();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--port" => {
                port = args.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| {
                    eprintln!("{}", usage());
                    std::process::exit(2);
                })
            }
            "--site" => {
                site = args.next().unwrap_or_else(|| {
                    eprintln!("{}", usage());
                    std::process::exit(2);
                })
            }
            "--dir" => {
                dir = PathBuf::from(args.next().unwrap_or_else(|| {
                    eprintln!("{}", usage());
                    std::process::exit(2);
                }))
            }
            "--max-connections" => {
                config.max_connections = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .filter(|&n| n > 0)
                    .unwrap_or_else(|| {
                        eprintln!("{}", usage());
                        std::process::exit(2);
                    })
            }
            "--help" | "-h" => {
                println!("{}", usage());
                return;
            }
            other => {
                eprintln!("unknown arg: {other}\n{}", usage());
                std::process::exit(2);
            }
        }
    }

    let mut store = SiteStore::new();
    match store.load_dir(&site, &dir) {
        Ok(n) => eprintln!(
            "loaded {n} page(s) for site '{site}' from {}",
            dir.display()
        ),
        Err(e) => {
            eprintln!("failed to load site dir {}: {e}", dir.display());
            std::process::exit(1);
        }
    }
    for (s, p) in store.routes() {
        eprintln!("  route: {s}/{p}");
    }

    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap_or_else(|e| {
        eprintln!("bind 127.0.0.1:{port}: {e}");
        std::process::exit(1);
    });
    eprintln!("nexus-server listening on 127.0.0.1:{port} (NXP/0.1)");
    if let Err(e) = nexus_server::serve_with_config(listener, store, config) {
        eprintln!("server error: {e}");
        std::process::exit(1);
    }
}
