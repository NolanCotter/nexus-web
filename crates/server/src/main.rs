use std::net::TcpListener;
use std::path::PathBuf;

use nexus_server::{ServerConfig, SiteStore};

fn usage() -> &'static str {
    "usage: nexus-server [--port PORT] [--site NAME] [--dir PATH] [--max-connections N] [--key PATH] [--record-ttl SECS] [--resign-interval SECS]"
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn main() {
    let mut port: u16 = 7843;
    let mut site = "example".to_string();
    let mut dir = PathBuf::from("sites/example");
    let mut config = ServerConfig::default();
    let mut key_path: Option<PathBuf> = None;
    let mut record_ttl: u64 = 86400;
    // Re-sign cadence; None = default to ttl/2 once --key is given.
    let mut resign_interval: Option<u64> = None;

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
            "--key" => {
                key_path = Some(PathBuf::from(args.next().unwrap_or_else(|| {
                    eprintln!("{}", usage());
                    std::process::exit(2);
                })));
            }
            "--record-ttl" => {
                record_ttl = args.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| {
                    eprintln!("{}", usage());
                    std::process::exit(2);
                })
            }
            "--resign-interval" => {
                resign_interval =
                    Some(args.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| {
                        eprintln!("{}", usage());
                        std::process::exit(2);
                    }))
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
    for name in store.endpoint_routes() {
        eprintln!("  endpoint records: {name}/@{name}");
    }

    // Optional identity: with --key, every page is signed at startup and
    // served over RECORDS. Missing key file is generated (0600); without
    // --key the server serves pages only and RECORDS answers 404.
    if let Some(path) = key_path {
        let identity = if path.exists() {
            nexus_identity::SiteIdentity::load_secret_key(&path).unwrap_or_else(|e| {
                eprintln!("load key {}: {e}", path.display());
                std::process::exit(1);
            })
        } else {
            let id = nexus_identity::SiteIdentity::generate_key_file(&path).unwrap_or_else(|e| {
                eprintln!("generate key {}: {e}", path.display());
                std::process::exit(1);
            });
            eprintln!("generated new site key at {}", path.display());
            id
        };
        eprintln!("site identity: {}", identity.site_id());
        match store.sign_pages(&identity, now_unix().saturating_add(record_ttl)) {
            Ok(n) => eprintln!("signed {n} record(s), ttl {record_ttl}s"),
            Err(e) => {
                eprintln!("sign pages: {e}");
                std::process::exit(1);
            }
        }
        // Background refresh (default ttl/2, --resign-interval overrides,
        // 0 disables) so records never expire on a long-lived server.
        let interval = resign_interval.unwrap_or(record_ttl / 2);
        if interval > 0 {
            store.set_signer(identity, record_ttl);
            config.resign_interval = Some(std::time::Duration::from_secs(interval.max(1)));
            eprintln!("record refresh every {}s", interval.max(1));
        }
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
