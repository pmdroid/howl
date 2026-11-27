use std::{
    env,
    net::{IpAddr, SocketAddr},
    process::ExitCode,
    sync::Arc,
};

use deadpool_postgres::{Manager, Pool};
use howl_control_plane::{ControlPlane, Error, GitHub, Id, Result, migrate};
use tokio_postgres::{Config, NoTls, config::Host};
use zeroize::Zeroizing;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("howl-control-plane startup failed: {error:?}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    let migrate_only = match args.as_slice() {
        [] => false,
        [flag] if flag == "--migrate" => true,
        _ => return Err(Error::Configuration),
    };
    let url = Zeroizing::new(required("HOWL_CONTROL_DATABASE_URL")?);
    let config: Config = url.parse().map_err(|_| Error::Configuration)?;
    if config.get_hosts().is_empty()
        || config.get_hostaddrs().iter().any(|ip| !ip.is_loopback())
        || !config.get_hosts().iter().all(|host| match host {
            Host::Tcp(host) => host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()),
            #[cfg(unix)]
            Host::Unix(path) => path.is_absolute(),
        })
    {
        return Err(Error::Configuration);
    }
    let pool = Pool::builder(Manager::new(config, NoTls))
        .max_size(12)
        .build()
        .map_err(|_| Error::Configuration)?;
    if migrate_only {
        return migrate(&pool).await;
    }
    let bind: SocketAddr = env::var("HOWL_CONTROL_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8080".into())
        .parse()
        .map_err(|_| Error::Configuration)?;
    if !bind.ip().is_loopback() {
        return Err(Error::Configuration);
    }
    let github = GitHub::new(
        required("HOWL_GITHUB_CLIENT_ID")?,
        Zeroizing::new(required("HOWL_GITHUB_CLIENT_SECRET")?),
    )?;
    let audience = configured_id("HOWL_CONTROL_AUDIENCE")?;
    let state_key = configured_id("HOWL_CONTROL_STATE_KEY")?;
    let control = Arc::new(ControlPlane::new(pool, github, *audience, state_key)?);
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|_| Error::Configuration)?;
    axum::serve(listener, control.router())
        .await
        .map_err(|_| Error::Internal)
}

fn required(name: &str) -> Result<String> {
    env::var(name).map_err(|_| Error::Configuration)
}

fn configured_id(name: &str) -> Result<Zeroizing<Id>> {
    let text = Zeroizing::new(required(name)?);
    let mut id = Zeroizing::new([0; 32]);
    hex::decode_to_slice(&*text, &mut *id).map_err(|_| Error::Configuration)?;
    Ok(id)
}
