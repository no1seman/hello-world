use std::convert::Infallible;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::{env, fs, io};

use clap::Parser;
use http::{header, Method, Request, Response, StatusCode};
use http_body_util::{Full, Empty};
use hyper::body::{Bytes, Incoming as IncomingBody};
use hyper::service::{service_fn, Service};
use hyper::Error;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use tokio::runtime::Runtime;
use tokio::{net::TcpListener, runtime::Builder as rtBuilder};
use tokio_rustls::TlsAcceptor;
use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[macro_use]
extern crate log;
extern crate pretty_env_logger;

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
}

type Counter = i32;

fn main() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(log::LevelFilter::Debug)
        .init();

    let p = env::current_dir().unwrap();
    info!("Current directory: {}", p.display());

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

    // Create http-server runtime
    let runtime = rtBuilder::new_multi_thread()
        .worker_threads(config.threads)
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
    // Build TLS configuration.
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| error(e.to_string()))?;
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

    rt.block_on(async move {
        let addr = SocketAddr::new(config.bind.into(), config.port);

        info!(
            "Starting to serve on https://{} with {} thread(s)",
            addr, config.threads
        );

        let svc = Svc {
            counter: Arc::new(Mutex::new(0)),
        };

        // Create a TCP listener via tokio.
        let listener = TcpListener::bind(&addr).await?;

        loop {
            let (tcp_stream, _remote_addr) = listener.accept().await?;

            let mut b1 = [0; 1];
            let n = tcp_stream.peek(&mut b1).await?;

            if n == 1 && b1[0] == 0x16 {
                // Seems that it's TLS
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
                // Non-TLS, need to redirect to HTTPS
                error!("Non TLS request! Permanent redirect to HTTPS");
                tokio::task::spawn(async move {
                    if let Err(err) = Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(tcp_stream), service_fn(permanent_redirect))
                        .await
                    {
                        error!("failed to serve connection: {err:#}");
                    }
                });
            };
        }
    })
}

async fn permanent_redirect(
    req: Request<impl hyper::body::Body>,
) -> Result<Response<Empty<Bytes>>, Infallible> {
    let host = req.headers().get("Host").unwrap().to_str().unwrap();
    Ok(Response::builder()
        .status(StatusCode::PERMANENT_REDIRECT)
        .header(
            header::LOCATION,
            format!("{}{}{}", "https://", host, req.uri().path()),
        )
        .body(Empty::new())
        .unwrap())
}

#[derive(Debug, Clone)]
struct Svc {
    counter: Arc<Mutex<Counter>>,
}

impl Service<Request<IncomingBody>> for Svc {
    type Response = Response<Full<Bytes>>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<IncomingBody>) -> Self::Future {
        #[inline(always)]
        fn mk_response(s: String) -> Result<Response<Full<Bytes>>, hyper::Error> {
            Ok(Response::builder().body(Full::new(Bytes::from(s))).unwrap())
        }

        #[inline(always)]
        fn mk_error(s: String, status: StatusCode) -> Result<Response<Full<Bytes>>, hyper::Error> {
            Ok(Response::builder()
                .status(status)
                .body(Full::new(Bytes::from(s)))
                .unwrap())
        }

        #[inline(always)]
        fn increase_counter(svc: &Svc) {
            *svc.counter.lock().expect("lock poisoned") += 1;
        }

        let res = match (req.method(), req.uri().path()) {
            (&Method::GET, "/") => {
                increase_counter(&self);
                mk_response(format!(
                    "home! counter = {:?}",
                    self.counter.lock().unwrap()
                ))
            }
            (&Method::GET, "/posts") => {
                increase_counter(&self);
                mk_response(format!(
                    "posts, of course! counter = {:?}",
                    self.counter.lock().unwrap()
                ))
            }
            (&Method::GET, "/authors") => {
                increase_counter(&self);
                mk_response(format!(
                    "authors extraordinare! counter = {:?}",
                    self.counter.lock().unwrap()
                ))
            }
            // Return the 404 Not Found for other routes, and don't increment counter.
            _ => {
                return Box::pin(async {
                    mk_error("oh no! not found".into(), StatusCode::NOT_FOUND)
                })
            }
        };

        Box::pin(async { res })
    }
}

// Load public certificate from file.
fn load_certs(filename: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    let certfile = fs::File::open(filename)
        .map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(certfile);

    rustls_pemfile::certs(&mut reader).collect()
}

// Load private key from file.
fn load_private_key(filename: &str) -> io::Result<PrivateKeyDer<'static>> {
    let keyfile = fs::File::open(filename)
        .map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(keyfile);

    rustls_pemfile::private_key(&mut reader).map(|key| key.unwrap())
}
