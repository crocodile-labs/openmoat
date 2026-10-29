//! The proxy end to end on loopback: a real listener, a local upstream server
//! and a resolver map instead of DNS. No external network.

use std::collections::HashMap;
use std::io::{self, Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Mutex;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use openmoat_core::{CompiledPolicy, EvalContext, Policy, Verdict};
use openmoat_proxy::{Broker, Connection, Limits, Proxy, RecordError, Recorder, Resolve, Sessions};

const POLICY: &str = r#"
version: 1
defaults: { "*": deny, fetch: ask }
deny:
  - id: no-doc-net
    net: ["203.0.113.7", "2001:db8::*"]
allow:
  - id: deny-names
    net: ["denied.test", "mixed-denied.test", "denied-v6.test"]
  - id: test-hosts
    # `loop.test:1`: a port the policy allows where no listed server listens
    net: ["allowed.test", "rebind.test", "mixed.test", "loop.test", "loop.test:1", "169.254.169.254", "owner.test", "127.0.0.1"]
  - id: lan-names
    net: ["lan.test", "mixed-lan.test", "*.wild.test"]
"#;

const UPSTREAM_REPLY: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
const WAIT: Duration = Duration::from_secs(5);

/// Names to addresses, standing in for DNS.
struct MapResolver(HashMap<&'static str, Vec<IpAddr>>);

impl Resolve for MapResolver {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let ips = self.0.get(host).ok_or(io::ErrorKind::NotFound)?;
        Ok(ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect())
    }
}

/// One recorded decision, as the audit log would store it.
#[derive(Debug, Clone)]
struct Row {
    tool: Option<String>,
    dest: Option<(String, u16)>,
    verdict: Verdict,
    rules: Vec<String>,
    reasons: Vec<String>,
    terminated: bool,
}

#[derive(Default)]
struct MemoryRecorder(Mutex<Vec<Row>>);

impl Recorder for MemoryRecorder {
    fn record(&self, c: &Connection<'_>) -> Result<(), RecordError> {
        self.0.lock().unwrap().push(Row {
            tool: c.method.map(str::to_owned),
            dest: c.destination.map(|(h, p)| (h.to_owned(), p)),
            verdict: c.decision.verdict,
            rules: c.decision.rules.clone(),
            reasons: c.decision.reasons.clone(),
            terminated: c.terminated,
        });
        Ok(())
    }
}

/// Fails every record, keeping the failures it is told about.
#[derive(Default)]
struct FailingRecorder(Mutex<Vec<String>>);

impl Recorder for FailingRecorder {
    fn record(&self, _: &Connection<'_>) -> Result<(), RecordError> {
        Err(RecordError("disk full".to_owned()))
    }

    fn unrecorded(&self, error: &RecordError) {
        self.0.lock().unwrap().push(error.to_string());
    }
}

/// A local server that reports the first bytes of each connection and answers
/// with `UPSTREAM_REPLY`.
fn upstream() -> (SocketAddr, Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            stream
                .set_read_timeout(Some(Duration::from_millis(500)))
                .unwrap();
            let mut buf = vec![0; 65536];
            let n = stream.read(&mut buf).unwrap_or(0);
            buf.truncate(n);
            let _ = tx.send(buf);
            let _ = stream.write_all(UPSTREAM_REPLY);
        }
    });
    (addr, rx)
}

/// `yaml` with each allowed host pattern also named on `port`, where the
/// local upstream listens: a pattern without a port allows 443 and 80 only.
fn on_port(yaml: &str, port: u16) -> Policy {
    let mut policy = Policy::parse(yaml).unwrap();
    for group in &mut policy.allow {
        let ported: Vec<String> = group
            .net
            .iter()
            .filter(|p| !p.contains(':'))
            .map(|p| format!("{p}:{port}"))
            .collect();
        group.net.extend(ported);
    }
    policy
}

struct Harness {
    proxy: SocketAddr,
    upstream: SocketAddr,
    received: Receiver<Vec<u8>>,
    rows: &'static MemoryRecorder,
}

fn start(recorder: Option<&'static dyn Recorder>, limits: Limits) -> Harness {
    launch(recorder, limits, Broker::default(), upstream())
}

fn launch(
    recorder: Option<&'static dyn Recorder>,
    limits: Limits,
    broker: Broker,
    upstream: (SocketAddr, Receiver<Vec<u8>>),
) -> Harness {
    launch_with(recorder, limits, broker, upstream, None)
}

fn launch_with(
    recorder: Option<&'static dyn Recorder>,
    limits: Limits,
    broker: Broker,
    (upstream, received): (SocketAddr, Receiver<Vec<u8>>),
    sessions: Option<&'static Sessions<'static>>,
) -> Harness {
    let rows: &'static MemoryRecorder = Box::leak(Box::default());
    let recorder = recorder.unwrap_or(rows);
    let local = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    let metadata = ip("169.254.169.254");
    let resolver = MapResolver(HashMap::from([
        ("allowed.test", vec![local]),
        ("rebind.test", vec![metadata]),
        ("mixed.test", vec![local, metadata]),
        ("loop.test", vec![local]),
        ("unknown.test", vec![local]),
        ("lan.test", vec![ip("10.0.0.5")]),
        (
            "mixed-lan.test",
            vec![ip("93.184.215.14"), ip("::ffff:192.168.1.1")],
        ),
        ("x.wild.test", vec![ip("fd12::1")]),
        ("owner.test", vec![local]),
        ("denied.test", vec![ip("203.0.113.7")]),
        // the listed local server first: it passes, the denied address after it does not
        ("mixed-denied.test", vec![local, ip("203.0.113.7")]),
        ("denied-v6.test", vec![ip("2001:db8::5")]),
    ]));
    let policy: &'static Policy = Box::leak(Box::new(on_port(POLICY, upstream.port())));
    let ctx = EvalContext {
        home: "/home/u".to_owned(),
        project: None,
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
        cwd: "/home/u".to_owned(),
        case_insensitive_paths: false,
    };
    let proxy = Proxy {
        policy: Box::leak(Box::new(CompiledPolicy::compile(policy, &ctx).unwrap())),
        resolver: Box::leak(Box::new(resolver)),
        recorder,
        limits: Box::leak(Box::new(limits)),
        loopback_ok: Box::leak(Box::new([upstream])),
        broker: Box::leak(Box::new(broker)),
        allow_ech: false,
        sessions,
        local: None,
        tls: None,
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || proxy.serve(&listener));
    Harness {
        proxy: addr,
        upstream,
        received,
        rows,
    }
}

impl Harness {
    fn connect(&self) -> TcpStream {
        let s = TcpStream::connect(self.proxy).unwrap();
        s.set_read_timeout(Some(WAIT)).unwrap();
        s
    }

    /// Send `request` and read until the proxy closes the connection.
    fn exchange(&self, request: &str) -> String {
        let mut s = self.connect();
        s.write_all(request.as_bytes()).unwrap();
        read_all(&mut s)
    }

    fn port(&self) -> u16 {
        self.upstream.port()
    }

    fn rows(&self) -> Vec<Row> {
        self.rows.0.lock().unwrap().clone()
    }

    fn nothing_forwarded(&self) -> bool {
        match self.received.recv_timeout(Duration::from_millis(300)) {
            Ok(bytes) => bytes.is_empty(),
            Err(_) => true,
        }
    }
}

fn read_all(s: &mut TcpStream) -> String {
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

/// A minimal TLS `ClientHello` record naming `sni`.
fn client_hello(sni: &str) -> Vec<u8> {
    client_hello_with(sni, &[])
}

/// [`client_hello`] with `extra` (whole extensions, type and length included)
/// after the SNI.
fn client_hello_with(sni: &str, extra: &[u8]) -> Vec<u8> {
    let be = |n: usize| u16::try_from(n).unwrap().to_be_bytes();
    let mut entry = vec![0];
    entry.extend(be(sni.len()));
    entry.extend(sni.as_bytes());
    let mut ext = vec![0, 0];
    ext.extend(be(entry.len() + 2));
    ext.extend(be(entry.len()));
    ext.extend(entry);
    ext.extend(extra);
    let mut body = vec![3, 3];
    body.extend([1; 32]);
    body.extend([0, 0, 2, 0x13, 0x01, 1, 0]);
    body.extend(be(ext.len()));
    body.extend(ext);
    let mut hs = vec![1, 0];
    hs.extend(be(body.len()));
    hs.extend(body);
    let mut record = vec![22, 3, 1];
    record.extend(be(hs.len()));
    record.extend(hs);
    record
}

/// Open a CONNECT tunnel to `host` and send a `ClientHello` naming `sni`.
fn tunnel(h: &Harness, host: &str, sni: &str) -> (TcpStream, String) {
    tunnel_with(h, host, &client_hello(sni))
}

/// Open a CONNECT tunnel to `host` and send `hello`.
fn tunnel_with(h: &Harness, host: &str, hello: &[u8]) -> (TcpStream, String) {
    let mut s = h.connect();
    write!(
        s,
        "CONNECT {host}:{} HTTP/1.1\r\nHost: {host}\r\n\r\n",
        h.port()
    )
    .unwrap();
    let mut established = [0u8; 39];
    s.read_exact(&mut established).unwrap();
    assert_eq!(&established, b"HTTP/1.1 200 Connection Established\r\n\r\n");
    s.write_all(hello).unwrap();
    let rest = read_all(&mut s);
    (s, rest)
}

mod broker;
mod http;
mod limits;
mod private;
mod sessions;
mod terminate;
mod tunnel;
