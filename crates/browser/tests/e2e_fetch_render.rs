//! End-to-end: real server data path over loopback TCP.
//! Serves the committed `sites/example/home.json` bytes, resolves via
//! LocalResolver, fetches via the browser stack, renders to text.

use std::net::TcpListener;

#[test]
fn example_home_renders_end_to_end() {
    let workspace =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../sites/example");
    let home_bytes = std::fs::read(workspace.join("home.json")).expect("home.json exists");

    let mut store = nexus_server::SiteStore::new();
    store.insert("example", "home", home_bytes);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        nexus_server::handle_one(&stream, &store).unwrap();
    });

    let mut resolver = nexus_resolver::LocalResolver::new();
    resolver
        .insert(
            "example",
            nexus_resolver::Route {
                endpoints: vec![addr.to_string()],
                pinned_site_id: None,
            },
        )
        .unwrap();

    let page = nexus_browser::navigate(&resolver, "example", "home").unwrap();
    assert_eq!(page.metadata.site, "example");
    let text = nexus_renderer::render_text(&page);
    assert!(text.contains("Hello, Nexus"));
}
