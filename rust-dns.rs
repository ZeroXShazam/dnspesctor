//! TCP-over-DNS tunnel: client listens on TCP and tunnels via TXT queries;
//! server runs a DNS server and forwards streams to a TCP destination.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use clap::Parser;
use clap::Subcommand;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::TXT;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::net::UdpSocket;

const CHUNK_SIZE: usize = 40; // fits in one DNS label as base64 (~54 chars)
const POLL_SEQ: u32 = 0;

fn encode_data_label(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn decode_data_label(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| e.into())
}

/// Build query name: [data_labels...].seq.stream_id.domain
fn build_query_name(stream_id: &str, seq: u32, data: &[u8], domain: &str) -> String {
    let mut labels = Vec::new();
    if seq != POLL_SEQ && !data.is_empty() {
        for chunk in data.chunks(CHUNK_SIZE * 3 / 4) {
            labels.push(encode_data_label(chunk));
        }
    }
    labels.push(seq.to_string());
    labels.push(stream_id.to_string());
    let name = format!("{}.{}", labels.join("."), domain);
    name
}

/// Parse query name: domain.stream_id.seq.[data_labels...]
/// Returns (stream_id, seq, data)
fn parse_query_name(qname: &str, domain: &str) -> Option<(String, u32, Vec<u8>)> {
    let suffix = format!(".{}", domain);
    let qname = qname.strip_suffix(&suffix)?;
    let parts: Vec<&str> = qname.split('.').collect();
    if parts.len() < 2 {
        return None;
    }
    let stream_id = parts[parts.len() - 1].to_string();
    let seq_str = parts[parts.len() - 2];
    let seq = seq_str.parse::<u32>().ok()?;
    let data_parts = &parts[..parts.len().saturating_sub(2)];
    let mut data = Vec::new();
    for p in data_parts {
        if let Ok(dec) = decode_data_label(p) {
            data.extend_from_slice(&dec);
        }
    }
    Some((stream_id, seq, data))
}

/// Response TXT: "OK" or "S<seq>D<base64data>"
fn encode_response_txt(seq: u32, data: &[u8]) -> String {
    if data.is_empty() {
        "OK".to_string()
    } else {
        format!("S{}D{}", seq, encode_data_label(data))
    }
}

fn decode_response_txt(txt: &str) -> Option<(u32, Vec<u8>)> {
    if txt == "OK" {
        return Some((0, vec![]));
    }
    let rest = txt.strip_prefix('S')?;
    let (seq_str, data_b64) = rest.split_once('D')?;
    let seq = seq_str.parse::<u32>().ok()?;
    let data = base64::engine::general_purpose::STANDARD.decode(data_b64).ok()?;
    Some((seq, data))
}

// ============== CLI ==============

#[derive(Parser, Debug)]
#[command(name = "dns-tunnel")]
#[command(about = "TCP-over-DNS tunnel: client and server")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run the tunnel client: listen on TCP, tunnel over DNS TXT
    Client {
        /// TCP address to listen on (e.g. 127.0.0.1:1080)
        #[arg(long, short = 'l', default_value = "127.0.0.1:1080")]
        listen: String,

        /// Comma-separated DNS server IPs (e.g. 8.8.8.8,1.1.1.1)
        #[arg(long, short = 'd', required = true)]
        dns_servers: String,

        /// Comma-separated domains for TXT queries (e.g. t1.example.com,t2.example.com)
        #[arg(long, short = 'm', required = true)]
        domains: String,

        /// DNS server port (default 53; use 5353 for local testing without root)
        #[arg(long, default_value = "53")]
        dns_port: u16,
    },

    /// Run the tunnel server: DNS server that forwards streams to a TCP destination
    Server {
        /// UDP address for DNS server (e.g. 0.0.0.0:53)
        #[arg(long, short = 'b', default_value = "0.0.0.0:53")]
        bind: String,

        /// Domain(s) to respond for, comma-separated (e.g. t1.example.com,t2.example.com)
        #[arg(long, short = 'd', required = true)]
        domain: String,

        /// TCP destination to forward streams to (e.g. 127.0.0.1:8080)
        #[arg(long, short = 't', required = true)]
        destination: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Client {
            listen,
            dns_servers,
            domains,
            dns_port,
        } => {
            let servers: Vec<String> = dns_servers.split(',').map(|s| s.trim().to_string()).collect();
            let domains: Vec<String> = domains.split(',').map(|s| s.trim().to_string()).collect();
            if servers.is_empty() || domains.is_empty() {
                eprintln!("Provide at least one DNS server and one domain");
                return Ok(());
            }
            run_client(&listen, &servers, &domains, dns_port).await?;
        }
        Commands::Server {
            bind,
            domain,
            destination,
        } => run_server(&bind, &domain, &destination).await?,
    }
    Ok(())
}

// ============== Server ==============

struct StreamState {
    /// Client → destination: send (seq, data) so writer can reorder
    tx: tokio::sync::mpsc::UnboundedSender<(u32, Vec<u8>)>,
    out_seq: u32,
    /// Destination → client: buffered replies to send on next TXT response
    out_buffer: Vec<(u32, Vec<u8>)>,
}

async fn run_server(
    bind_addr: &str,
    domain: &str,
    destination: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind(bind_addr).await?;
    let domains: Vec<String> = domain
        .split(',')
        .map(|s| s.trim().trim_end_matches('.').to_string())
        .collect();
    println!("DNS tunnel server on {}, domains {:?}, destination {}", bind_addr, domains, destination);
    let streams: Arc<Mutex<BTreeMap<String, Arc<Mutex<StreamState>>>>> = Arc::new(Mutex::new(BTreeMap::new()));
    let mut buf = [0u8; 512];

    loop {
        let (len, src) = socket.recv_from(&mut buf).await?;
        let req = match Message::from_vec(&buf[..len]) {
            Ok(r) => r,
            _ => continue,
        };

        let mut resp = Message::new();
        resp.set_id(req.id());
        resp.set_message_type(MessageType::Response);
        resp.set_op_code(req.op_code());
        resp.set_authoritative(true);

            if let Some(query) = req.queries().first() {
                resp.add_query(query.clone());
                let qname = query.name().to_utf8();

                let parsed = domains.iter().find_map(|d| parse_query_name(&qname, d));
                if let Some((stream_id, seq, data)) = parsed {
                    let state = get_or_create_stream(streams.clone(), &stream_id, destination).await;
                    if let Some(st) = state {
                        if seq != POLL_SEQ && !data.is_empty() {
                            let _ = st.lock().await.tx.send((seq, data));
                        }
                        let txt = take_next_buffered(&st).await;
                    let name = Name::from_utf8(&qname)?;
                    let mut record = Record::new();
                    record.set_name(name);
                    record.set_ttl(1);
                    record.set_rr_type(RecordType::TXT);
                    record.set_data(Some(RData::TXT(TXT::new(vec![txt]))));
                    resp.add_answer(record);
                }
            }
        }

        resp.set_response_code(ResponseCode::NoError);
        let mut out = Vec::with_capacity(512);
        let mut encoder = BinEncoder::new(&mut out);
        resp.emit(&mut encoder)?;
        let _ = socket.send_to(&out, &src).await;
    }
}

async fn get_or_create_stream(
    streams: Arc<Mutex<BTreeMap<String, Arc<Mutex<StreamState>>>>>,
    stream_id: &str,
    destination: &str,
) -> Option<Arc<Mutex<StreamState>>> {
    {
        let g = streams.lock().await;
        if let Some(s) = g.get(stream_id) {
            return Some(s.clone());
        }
    }
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(u32, Vec<u8>)>();
    let dest = destination.to_string();
    let stream_id_owned = stream_id.to_string();
    let state = Arc::new(Mutex::new(StreamState {
        tx: tx.clone(),
        out_seq: 0,
        out_buffer: Vec::new(),
    }));
    {
        let mut g = streams.lock().await;
        if g.contains_key(stream_id) {
            return g.get(stream_id).cloned();
        }
        g.insert(stream_id.to_string(), state.clone());
    }

    let state_clone = state.clone();
    tokio::spawn(async move {
        let tcp = match TcpStream::connect(&dest).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("stream {}: connect to {} failed: {}", stream_id_owned, dest, e);
                return;
            }
        };
        let (mut reader, mut writer) = tokio::io::split(tcp);

        let state_for_reader = state_clone.clone();
        let reader_handle = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        let chunk = buf[..n].to_vec();
                        let mut st = state_for_reader.lock().await;
                        let seq = st.out_seq.wrapping_add(1);
                        st.out_seq = seq;
                        st.out_buffer.push((seq, chunk));
                    }
                    Err(_) => break,
                }
            }
        });

        let writer_handle = tokio::spawn(async move {
            let mut next_seq: u32 = 1;
            let mut reorder: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
            loop {
                match rx.recv().await {
                    None => break,
                    Some((seq, data)) => {
                        reorder.insert(seq, data);
                        while let Some(chunk) = reorder.remove(&next_seq) {
                            if writer.write_all(&chunk).await.is_err() {
                                return;
                            }
                            next_seq = next_seq.wrapping_add(1);
                        }
                    }
                }
            }
            let _ = writer.shutdown().await;
        });

        let _ = reader_handle.await;
        let _ = writer_handle.await;
    });

    Some(state)
}

async fn take_next_buffered(state: &Arc<Mutex<StreamState>>) -> String {
    let mut st = state.lock().await;
    if let Some((seq, data)) = st.out_buffer.first() {
        let seq = *seq;
        let data = data.clone();
        st.out_buffer.remove(0);
        return encode_response_txt(seq, &data);
    }
    "OK".to_string()
}

// ============== Client ==============

async fn run_client(
    listen_addr: &str,
    dns_servers: &[String],
    domains: &[String],
    dns_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(listen_addr).await?;
    println!("DNS tunnel client on {}, {} servers, {} domains (port {})", listen_addr, dns_servers.len(), domains.len(), dns_port);

    let resolvers: Vec<TokioAsyncResolver> = dns_servers
        .iter()
        .map(|s| {
            let ip: std::net::IpAddr = s.parse().unwrap();
            TokioAsyncResolver::tokio(
                ResolverConfig::from_parts(
                    None,
                    vec![],
                    NameServerConfigGroup::from_ips_clear(&[ip], dns_port, true),
                ),
                ResolverOpts::default(),
            )
        })
        .collect();
    let resolvers = Arc::new(resolvers);
    let domains = Arc::new(domains.to_vec());

    while let Ok((stream, addr)) = listener.accept().await {
        let stream_id = format!("{:08x}", rand::thread_rng().gen::<u32>());
        let resolvers = resolvers.clone();
        let domains = domains.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client_connection(stream, stream_id, resolvers, &domains).await {
                eprintln!("connection {}: {}", addr, e);
            }
        });
    }
    Ok(())
}

async fn handle_client_connection(
    client: TcpStream,
    stream_id: String,
    resolvers: Arc<Vec<TokioAsyncResolver>>,
    domains: &[String],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (mut client_read, mut client_write) = tokio::io::split(client);

    let (tx_from_remote, mut rx_from_remote) = tokio::sync::mpsc::unbounded_channel::<(u32, Vec<u8>)>();

    let resolvers_reader = resolvers.clone();
    let domains_reader = domains.to_vec();
    let stream_id_clone = stream_id.clone();
    tokio::spawn(async move {
        let mut seq: u32 = 1;
        let mut buf = [0u8; 4096];
        loop {
            match client_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let chunk = buf[..n].to_vec();
                    for c in chunk.chunks(CHUNK_SIZE) {
                        let domain = &domains_reader[rand::thread_rng().gen_range(0..domains_reader.len())];
                        let resolver = &resolvers_reader[rand::thread_rng().gen_range(0..resolvers_reader.len())];
                        let name = build_query_name(&stream_id_clone, seq, c, domain);
                        seq = seq.wrapping_add(1);
                        let _ = do_txt_lookup(resolver, &name).await;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let resolvers_poll = resolvers.clone();
    let domains_poll = domains.to_vec();
    let stream_id_poll = stream_id.clone();
    let tx_from_remote = tx_from_remote.clone();
    tokio::spawn(async move {
        let mut poll_interval = tokio::time::interval(Duration::from_millis(50));
        loop {
            poll_interval.tick().await;
            let domain = &domains_poll[rand::thread_rng().gen_range(0..domains_poll.len())];
            let resolver = &resolvers_poll[rand::thread_rng().gen_range(0..resolvers_poll.len())];
            let name = build_query_name(&stream_id_poll, POLL_SEQ, &[], domain);
            if let Ok(txt) = do_txt_lookup(resolver, &name).await {
                if let Some((seq, data)) = decode_response_txt(&txt) {
                    if !data.is_empty() {
                        let _ = tx_from_remote.send((seq, data));
                    }
                }
            }
        }
    });

    let mut next_seq = 1u32;
    let mut reorder: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    loop {
        match rx_from_remote.recv().await {
            None => break,
            Some((seq, data)) => {
                reorder.insert(seq, data);
                while let Some(chunk) = reorder.remove(&next_seq) {
                    client_write.write_all(&chunk).await?;
                    next_seq = next_seq.wrapping_add(1);
                }
            }
        }
    }
    let _ = client_write.shutdown().await;
    Ok(())
}

async fn do_txt_lookup(
    resolver: &TokioAsyncResolver,
    name: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let response = resolver.txt_lookup(name).await?;
    let record = response.iter().next().ok_or("no TXT record")?;
    let data = record.txt_data().first().ok_or("empty TXT")?;
    Ok(String::from_utf8_lossy(data).into_owned())
}
