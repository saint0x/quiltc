mod api;
mod db;
mod quilt_http;
mod services;
mod tls;
mod types;

use anyhow::{Context, Result};
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use api::nodes::AppState;
use quilt_http::{QuiltAuth, QuiltHttpClient};
use services::{heartbeat_monitor, SimpleIPAM, SimpleScheduler};

#[derive(Parser, Debug)]
#[command(name = "quilt-mesh-control")]
#[command(about = "Quilt Mesh control plane", long_about = None)]
struct Args {
    /// Bind address for HTTP server
    #[arg(long, default_value = "0.0.0.0:8080")]
    bind: String,

    /// Database file path
    #[arg(long)]
    db_path: Option<PathBuf>,

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,

    /// TLS certificate file (PEM)
    #[arg(long)]
    tls_cert: Option<PathBuf>,

    /// TLS private key file (PEM)
    #[arg(long)]
    tls_key: Option<PathBuf>,

    /// CA certificate for client verification (enables mTLS)
    #[arg(long)]
    tls_ca: Option<PathBuf>,

    /// Quilt backend base URL (enables HTTP proxy for /api/containers, /api/snapshots, /api/operations, /api/volumes, /api/auth, /api/api-keys, /api/events)
    #[arg(long, env = "QUILT_API_BASE_URL")]
    quilt_api_base_url: Option<String>,

    /// Quilt tenant API key (sent as X-Api-Key)
    #[arg(long, env = "QUILT_API_KEY")]
    quilt_api_key: Option<String>,

    /// Quilt JWT (sent as Authorization: Bearer ...)
    #[arg(long, env = "QUILT_JWT")]
    quilt_jwt: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let log_level = match args.log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let subscriber = FmtSubscriber::builder().with_max_level(log_level).finish();

    tracing::subscriber::set_global_default(subscriber)?;

    info!("Starting Quilt Mesh Control Plane");

    // Initialize database
    let db = db::init_db(args.db_path)?;

    // Initialize IPAM (find highest allocated subnet)
    let max_subnet_id =
        db::execute_async(&db, |conn| services::node_registry::get_max_subnet_id(conn)).await?;

    let ipam = if max_subnet_id > 0 {
        info!(
            "Initializing IPAM from database (max subnet ID: {})",
            max_subnet_id
        );
        Arc::new(SimpleIPAM::init_from_db(max_subnet_id))
    } else {
        info!("Initializing fresh IPAM");
        Arc::new(SimpleIPAM::new())
    };

    // Create scheduler
    let scheduler = Arc::new(SimpleScheduler::new());

    // Optional Quilt backend proxy client
    let quilt = if let Some(base_url) = &args.quilt_api_base_url {
        let auth = if let Some(k) = &args.quilt_api_key {
            Some(QuiltAuth::ApiKey(Arc::<str>::from(k.as_str())))
        } else if let Some(jwt) = &args.quilt_jwt {
            Some(QuiltAuth::BearerToken(Arc::<str>::from(jwt.as_str())))
        } else {
            None
        };

        Some(Arc::new(
            QuiltHttpClient::new(base_url, auth)
                .context("Failed to create Quilt HTTP proxy client")?,
        ))
    } else {
        None
    };

    // Create application state
    let state = Arc::new(AppState {
        db: db.clone(),
        ipam,
        scheduler,
        quilt,
    });

    // Start heartbeat monitor in background
    tokio::spawn(async move {
        if let Err(e) = heartbeat_monitor(db).await {
            tracing::error!("Heartbeat monitor failed: {}", e);
        }
    });

    // Create router
    let app = api::create_router(state);

    // Parse bind address
    let addr: SocketAddr = args.bind.parse()?;

    // Start server (with or without TLS)
    if let (Some(cert_path), Some(key_path)) = (&args.tls_cert, &args.tls_key) {
        info!("Starting HTTPS server on {} (TLS enabled)", addr);

        let tls_config = tls::load_server_config(cert_path, key_path, args.tls_ca.as_deref())?;

        let rustls_config =
            axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls_config));

        axum_server::bind_rustls(addr, rustls_config)
            .serve(app.into_make_service())
            .await?;
    } else {
        info!("Listening on http://{}", addr);

        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await?;
    }

    info!("Control plane shutdown complete");

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Shutdown signal received, draining connections...");
}
