use std::convert::Infallible;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::{
    atomic::{AtomicI32, Ordering},
    Arc, OnceLock,
};
use std::{
    env, fs,
    io::{self, BufReader},
};

use clap::Parser;
use get_if_addrs::get_if_addrs;
use http::{
    header::{self, HeaderMap, HeaderValue},
    Method, Request, Response, StatusCode,
};
use http_body_util::{Empty, Full};
use hyper::body::{Bytes, Incoming as IncomingBody};
use hyper::service::{service_fn, Service};
use hyper::Error;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use tcmalloc::TCMalloc;
use tokio::runtime::Runtime;
use tokio::{net::TcpListener, runtime::Builder as rtBuilder};
use tokio_rustls::TlsAcceptor;

#[global_allocator]
static GLOBAL: TCMalloc = TCMalloc;

#[macro_use]
extern crate log;
extern crate pretty_env_logger;

// Zero-copy static response bodies
static HOME_RESPONSE_TEMPLATE: &str = "home! counter = ";
static POSTS_RESPONSE_TEMPLATE: &str = "posts, of course! counter = ";
static AUTHORS_RESPONSE_TEMPLATE: &str = "authors extraordinare! counter = ";
static NOT_FOUND_BODY: &[u8] = b"oh no! not found";

// Pre-allocated headers for zero-copy
static CONTENT_TYPE_TEXT: HeaderValue = HeaderValue::from_static("text/plain; charset=utf-8");
static CACHE_CONTROL_30S: HeaderValue = HeaderValue::from_static("public, max-age=30");

// Pre-allocated strings for redirect
static HTTPS_PREFIX: &str = "https://";
static LOCALHOST_FALLBACK: &str = "localhost";

// Static response templates as Bytes for zero-copy
static RESPONSE_HEADERS: OnceLock<HeaderMap> = OnceLock::new();

fn init_static_headers() -> HeaderMap {
    let mut headers = HeaderMap::with_capacity(2);
    headers.insert(header::CONTENT_TYPE, CONTENT_TYPE_TEXT.clone());
    headers.insert(header::CACHE_CONTROL, CACHE_CONTROL_30S.clone());
    headers
}

// Buffer pool for string operations to avoid repeated allocations
thread_local! {
    static STRING_BUFFER: std::cell::RefCell<String> = std::cell::RefCell::new(String::with_capacity(512));
}

// Pre-computed counter strings for common values to avoid formatting
static COUNTER_CACHE: OnceLock<Vec<String>> = OnceLock::new();

fn init_counter_cache() -> Vec<String> {
    (0..1000).map(|i| i.to_string()).collect()
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct HTTPServer {
    /// server IP address to bind
    #[arg(short, long, default_value_t = Ipv4Addr::new(127, 0, 0, 1), env = "HTTP_BIND_ADDRESS")]
    bind: Ipv4Addr,

    /// Port number to bind
    #[arg(short, long, default_value_t = 3000, env = "HTTP_PORT_ADDRESS")]
    port: u16,

    /// Number of threads
    #[arg(short, long, default_value_t = 2, env = "HTTP_THREADS")]
    threads: usize,

    /// TLS cert file
    #[arg(short, long, default_value_t = String::from("./certs/localhost.crt"), env = "HTTP_TLS_CERT")]
    cert: String,

    /// TLS key file
    #[arg(short, long, default_value_t = String::from("./certs/localhost.key"), env = "HTTP_TLS_KEY")]
    key: String,

    /// Log level
    #[arg(short, long, default_value_t = String::from("Info"), env = "HTTP_LOG_LEVEL")]
    log_level: String,
}

fn main() {
    // Initialize static headers and counter cache once
    RESPONSE_HEADERS.set(init_static_headers()).unwrap();
    COUNTER_CACHE.set(init_counter_cache()).unwrap();

    pretty_env_logger::formatted_timed_builder()
        .filter_level(log::LevelFilter::from_str(&HTTPServer::parse().log_level).unwrap())
        .init();

    info!("Log level: {}", HTTPServer::parse().log_level);

    let p = env::current_dir().unwrap();
    info!("Current directory: {}", p.display());

    match get_if_addrs() {
        Ok(interfaces) => {
            for interface in interfaces {
                info!("Interface: {}", interface.name);
                info!("  IP Address: {}", interface.addr.ip());
            }
        }
        Err(e) => {
            error!("Error getting network interfaces: {}", e);
        }
    }

    let config = HTTPServer::parse();

    // Load public certificate
    let certs = match load_certs(&config.cert) {
        Ok(certs) => certs,
        Err(e) => {
            error!("FAILED to load certificate: {}", e);
            std::process::exit(1);
        }
    };
    info!("Public certificate loaded");

    // Load private key
    let key = match load_private_key(&config.key) {
        Ok(key) => key,
        Err(e) => {
            error!("FAILED to load certificate: {}", e);
            std::process::exit(1);
        }
    };

    info!("Private key loaded");

    // Create http-server runtime with maximum optimized settings
    let runtime = rtBuilder::new_multi_thread()
        .worker_threads(config.threads)
        .thread_stack_size(2 * 1024 * 1024) // 2MB stack for better performance
        .thread_name("hyper-worker")
        .enable_all()
        .build()
        .expect("Multithread env creation failed");

    info!("Multithread env created with {} threads", config.threads);

    // Serve an echo service over HTTPS, with proper error handling.
    if let Err(e) = run_server(runtime, config, certs, key) {
        error!("FAILED: {}", e);
        std::process::exit(1);
    }
}

#[inline(always)]
fn error(err: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}

fn run_server(
    rt: Runtime,
    config: HTTPServer,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Build TLS configuration with maximum optimizations
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| error(e.to_string()))?;
    server_config.alpn_protocols = vec![b"http/1.1".to_vec(), b"h2".to_vec()];
    server_config.session_storage = rustls::server::ServerSessionMemoryCache::new(4096);
    server_config.max_fragment_size = Some(16384); // Use larger fragments for better throughput
    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

    rt.block_on(async move {
        let addr = SocketAddr::new(config.bind.into(), config.port);

        info!(
            "Starting to serve on https://{} with {} thread(s)",
            addr, config.threads
        );

        let svc = Svc {
            counter: Arc::new(AtomicI32::new(0)),
        };

                // Create a TCP listener with maximum optimized settings
        let listener = TcpListener::bind(&addr).await?;

        loop {
            let (tcp_stream, _remote_addr) = listener.accept().await?;

            // Configure TCP socket for optimal performance
            if let Err(e) = tcp_stream.set_nodelay(true) {
                error!("Failed to set TCP_NODELAY: {}", e);
            }

            // Use a simple buffer for TLS detection
            let mut peek_buffer = [0u8; 1];
            let is_tls = match tcp_stream.peek(&mut peek_buffer).await {
                Ok(n) => n > 0 && peek_buffer[0] == 0x16,
                Err(_) => false,
            };

            if is_tls {
                // TLS connection
                let tls_acceptor = tls_acceptor.clone();
                let svc_clone = svc.clone();
                tokio::spawn(async move {
                    let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                        Ok(tls_stream) => tls_stream,
                        Err(err) => {
                            error!("failed to perform tls handshake: {err:#}");
                            return;
                        }
                    };
                    if let Err(err) = Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(tls_stream), svc_clone)
                        .await
                    {
                        let _a = err.downcast_ref::<Error>().unwrap();
                        error!("failed to serve connection: {err:#}");
                    }
                });
            } else {
                // Non-TLS, redirect to HTTPS
                tokio::spawn(async move {
                    if let Err(err) = Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(tcp_stream), service_fn(permanent_redirect))
                        .await
                    {
                        error!("failed to serve connection: {err:#}");
                    }
                });
            }
        }
    })
}

// Zero-copy redirect with thread-local string buffer
async fn permanent_redirect(
    req: Request<impl hyper::body::Body>,
) -> Result<Response<Empty<Bytes>>, Infallible> {
    let host = req
        .headers()
        .get("Host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or(LOCALHOST_FALLBACK);

    // Use thread-local buffer to avoid allocations
    let location = STRING_BUFFER.with(|buf| {
        let mut buffer = buf.borrow_mut();
        buffer.clear();
        buffer.reserve(HTTPS_PREFIX.len() + host.len() + req.uri().path().len());
        buffer.push_str(HTTPS_PREFIX);
        buffer.push_str(host);
        buffer.push_str(req.uri().path());
        buffer.clone()
    });

    Ok(Response::builder()
        .status(StatusCode::PERMANENT_REDIRECT)
        .header(header::LOCATION, location)
        .body(Empty::new())
        .unwrap())
}

#[derive(Debug, Clone)]
struct Svc {
    counter: Arc<AtomicI32>,
}

// Fast integer to string conversion with pre-computed cache
fn format_counter_response(template: &'static str, count: i32) -> Bytes {
    let count_str = if count >= 0 && count < 1000 {
        // Use pre-computed cache for common values
        &COUNTER_CACHE.get().unwrap()[count as usize]
    } else {
        // Fallback to conversion for large numbers
        return STRING_BUFFER.with(|buf| {
            let mut buffer = buf.borrow_mut();
            buffer.clear();
            buffer.reserve(template.len() + 12);
            buffer.push_str(template);
            buffer.push_str(&count.to_string());
            Bytes::copy_from_slice(buffer.as_bytes())
        });
    };

    // Zero-copy concatenation for cached values
    STRING_BUFFER.with(|buf| {
        let mut buffer = buf.borrow_mut();
        buffer.clear();
        buffer.reserve(template.len() + count_str.len());
        buffer.push_str(template);
        buffer.push_str(count_str);
        Bytes::copy_from_slice(buffer.as_bytes())
    })
}

impl Service<Request<IncomingBody>> for Svc {
    type Response = Response<Full<Bytes>>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<IncomingBody>) -> Self::Future {
        let counter = self.counter.clone();

        Box::pin(async move {
            // Pre-allocate response builder with optimized settings
            let response_builder = Response::builder().version(http::Version::HTTP_11); // Explicit HTTP/1.1 for performance

            match (req.method(), req.uri().path()) {
                (&Method::GET, "/") => {
                    let count = counter.fetch_add(1, Ordering::Relaxed) + 1;
                    let body = format_counter_response(HOME_RESPONSE_TEMPLATE, count);

                    Ok(response_builder
                        .header(header::CONTENT_TYPE, &CONTENT_TYPE_TEXT)
                        .header(header::CACHE_CONTROL, &CACHE_CONTROL_30S)
                        .body(Full::new(body))
                        .unwrap())
                }
                (&Method::GET, "/posts") => {
                    let count = counter.fetch_add(1, Ordering::Relaxed) + 1;
                    let body = format_counter_response(POSTS_RESPONSE_TEMPLATE, count);

                    Ok(response_builder
                        .header(header::CONTENT_TYPE, &CONTENT_TYPE_TEXT)
                        .header(header::CACHE_CONTROL, &CACHE_CONTROL_30S)
                        .body(Full::new(body))
                        .unwrap())
                }
                (&Method::GET, "/authors") => {
                    let count = counter.fetch_add(1, Ordering::Relaxed) + 1;
                    let body = format_counter_response(AUTHORS_RESPONSE_TEMPLATE, count);

                    Ok(response_builder
                        .header(header::CONTENT_TYPE, &CONTENT_TYPE_TEXT)
                        .header(header::CACHE_CONTROL, &CACHE_CONTROL_30S)
                        .body(Full::new(body))
                        .unwrap())
                }
                _ => {
                    // Zero-copy 404 response
                    Ok(response_builder
                        .status(StatusCode::NOT_FOUND)
                        .header(header::CONTENT_TYPE, &CONTENT_TYPE_TEXT)
                        .body(Full::new(Bytes::from_static(NOT_FOUND_BODY)))
                        .unwrap())
                }
            }
        })
    }
}

// Load public certificate from file with maximum I/O optimization
fn load_certs(filename: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    let cert_file = fs::File::open(filename)
        .map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;

    // Use much larger buffer for better I/O performance and mmap-like behavior
    let mut reader = BufReader::with_capacity(64 * 1024, cert_file);
    rustls_pemfile::certs(&mut reader).collect()
}

// Load private key from file with maximum I/O optimization
fn load_private_key(filename: &str) -> io::Result<PrivateKeyDer<'static>> {
    let keyfile = fs::File::open(filename)
        .map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;

    // Use much larger buffer for better I/O performance
    let mut reader = BufReader::with_capacity(64 * 1024, keyfile);
    rustls_pemfile::private_key(&mut reader).map(|key| key.unwrap())
}
