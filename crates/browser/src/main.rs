use nexus_browser::{navigate_cached, navigate_cached_verified, CacheStatus, OfflineCache};
use nexus_resolver::{LocalResolver, Route};

fn usage() -> &'static str {
    "usage: nexus-browser [--server HOST:PORT] [--site NAME] [--path PATH] [--pin SITE_ID]"
}

fn main() {
    let mut server = "127.0.0.1:7843".to_string();
    let mut site = "example".to_string();
    let mut path = "home".to_string();
    let mut pin: Option<String> = None;

    let mut args = std::env::args().skip(1).peekable();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--server" => {
                server = args.next().unwrap_or_else(|| {
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
            "--path" => {
                path = args.next().unwrap_or_else(|| {
                    eprintln!("{}", usage());
                    std::process::exit(2);
                })
            }
            "--pin" => {
                pin = Some(args.next().unwrap_or_else(|| {
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

    // M1: petname resolver with a single static entry pointing at --server.
    // Distributed resolution plugs in behind the same Resolver trait later.
    let mut resolver = LocalResolver::new();
    if let Err(e) = resolver.insert(
        &site,
        Route {
            endpoints: vec![server.clone()],
            pinned_site_id: pin.clone(),
        },
    ) {
        eprintln!("bad site name '{site}': {e}");
        std::process::exit(2);
    }

    // Pinned fetches verify against the record chain and fall back to the
    // verified cache offline; unpinned fetches use the plain cache path.
    // (The two paths share one index: an unverified `put` supersedes a
    // verified entry, so a pin can never be satisfied by unpinned bytes.)
    let cache = OfflineCache::open_default();
    let result = if pin.is_some() {
        navigate_cached_verified(&resolver, &cache, &site, &path)
    } else {
        navigate_cached(&resolver, &cache, &site, &path)
    };
    match result {
        Ok((page, status)) => {
            match status {
                CacheStatus::Fresh => {}
                CacheStatus::Stale => println!("[STALE (offline)] served from local cache"),
                CacheStatus::StaleVerified => {
                    println!("[STALE VERIFIED (offline)] served from local cache")
                }
            }
            print!("{}", nexus_renderer::render_text(&page));
        }
        Err(e) => {
            eprintln!("fetch {site}/{path} from {server}: {e}");
            std::process::exit(1);
        }
    }
}
