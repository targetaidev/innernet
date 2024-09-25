use anyhow::{anyhow, bail};
use colored::*;
use db::{DatabaseCidr, DatabasePeer};
use hyper::{http, server::conn::AddrStream, Body, Request, Response};
use ipnet::IpNet;
use parking_lot::{Mutex, RwLock};
use publicip::Preference;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use shared::{
    get_local_addrs,
    interface_config::{InterfaceConfig, InterfaceInfo, ServerInfo},
    wg, CidrContents, CidrTree, IoErrorContext, IpNetExt, NetworkOpts, PeerContents,
    INNERNET_PUBKEY_HEADER, PERSISTENT_KEEPALIVE_INTERVAL_SECS,
};
use std::{
    collections::{HashMap, VecDeque},
    convert::TryInto,
    env,
    fs::File,
    io::prelude::*,
    net::{IpAddr, SocketAddr, TcpListener},
    ops::Deref,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
    time::SystemTime,
};
use subtle::ConstantTimeEq;
use wireguard_control::{Backend, Device, DeviceUpdate, Key, KeyPair, PeerConfigBuilder};

mod api;
mod db;
mod error;
#[cfg(test)]
mod test;
mod util;

pub use error::ServerError;
pub use wireguard_control::InterfaceName;

const VERSION: &str = env!("CARGO_PKG_VERSION");

type Db = Arc<Mutex<Connection>>;
type Endpoints = Arc<RwLock<HashMap<String, SocketAddr>>>;

#[derive(Clone)]
pub struct Context {
    pub db: Db,
    pub endpoints: Endpoints,
    pub interface: InterfaceName,
    pub backend: Backend,
    pub public_key: Key,
}

pub struct Session {
    pub context: Context,
    pub peer: DatabasePeer,
}

impl Session {
    pub fn admin_capable(&self) -> bool {
        self.peer.is_admin && self.user_capable()
    }

    pub fn user_capable(&self) -> bool {
        !self.peer.is_disabled && self.peer.is_redeemed
    }

    pub fn redeemable(&self) -> bool {
        !self.peer.is_disabled && !self.peer.is_redeemed
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct ConfigFile {
    /// The server's WireGuard key
    pub private_key: String,

    /// The listen port of the server
    pub listen_port: u16,

    /// The internal WireGuard IP address assigned to the server
    pub address: IpAddr,

    /// The CIDR prefix of the WireGuard network
    pub network_cidr_prefix: u8,
}

impl ConfigFile {
    pub fn write_to_path<P: AsRef<Path>>(&self, path: P) -> Result<(), shared::Error> {
        let mut invitation_file = File::create(&path).with_path(&path)?;
        shared::chmod(&invitation_file, 0o600)?;
        invitation_file
            .write_all(toml::to_string(self).unwrap().as_bytes())
            .with_path(path)?;
        Ok(())
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, shared::Error> {
        let path = path.as_ref();
        let file = File::open(path).with_path(path)?;
        if shared::chmod(&file, 0o600)? {
            println!(
                "{} updated permissions for {} to 0600.",
                "[!]".yellow(),
                path.display()
            );
        }
        Ok(toml::from_str(
            &std::fs::read_to_string(path).with_path(path)?,
        )?)
    }
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
}

impl ServerConfig {
    pub fn new(config_dir: PathBuf, data_dir: PathBuf) -> Self {
        Self {
            config_dir,
            data_dir,
        }
    }

    pub fn database_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn database_path(&self, interface: &InterfaceName) -> PathBuf {
        PathBuf::new()
            .join(self.database_dir())
            .join(interface.to_string())
            .with_extension("db")
    }

    pub fn config_dir(&self) -> &Path {
        &self.config_dir
    }

    pub fn config_path(&self, interface: &InterfaceName) -> PathBuf {
        PathBuf::new()
            .join(self.config_dir())
            .join(interface.to_string())
            .with_extension("conf")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitializeOpts {
    /// The network name (ex: evilcorp)
    pub network_name: InterfaceName,

    /// The network CIDR (ex: 10.42.0.0/16)
    pub network_cidr: IpNet,

    /// Port to listen on (for the WireGuard interface)
    pub listen_port: u16,

    /// This server's external endpoint (ex: 100.100.100.100:51820)
    pub external_endpoint: Option<shared::Endpoint>,
}

fn create_database<P: AsRef<Path>>(database_path: P) -> Result<Connection, rusqlite::Error> {
    let conn = Connection::open(&database_path)?;
    conn.pragma_update(None, "foreign_keys", 1)?;
    conn.execute(db::peer::CREATE_TABLE_SQL, params![])?;
    conn.execute(db::association::CREATE_TABLE_SQL, params![])?;
    conn.execute(db::cidr::CREATE_TABLE_SQL, params![])?;
    conn.pragma_update(None, "user_version", db::CURRENT_VERSION)?;
    log::debug!("set database version to db::CURRENT_VERSION");

    Ok(conn)
}

fn open_database_connection(
    interface: &InterfaceName,
    conf: &ServerConfig,
) -> Result<rusqlite::Connection, shared::Error> {
    let database_path = conf.database_path(interface);
    if !Path::new(&database_path).exists() {
        bail!(
            "no database file found at {}",
            database_path.to_string_lossy()
        );
    }

    let conn = Connection::open(&database_path)?;
    // Foreign key constraints aren't on in SQLite by default. Enable.
    conn.pragma_update(None, "foreign_keys", 1)?;
    db::auto_migrate(&conn)?;
    Ok(conn)
}

const SERVER_NAME: &str = "innernet-server";

fn ensure_root_cidr(
    conn: &Connection,
    cidrs: &mut Vec<shared::Cidr>,
    network_name: &InterfaceName,
    network_cidr: &IpNet,
) -> Result<shared::Cidr, shared::Error> {
    match cidrs
        .iter()
        .position(|cidr| cidr.name == network_name.to_string())
    {
        Some(cidr_index) => Ok(cidrs.swap_remove(cidr_index)),
        None => {
            let cidr = DatabaseCidr::create(
                conn,
                CidrContents {
                    name: network_name.to_string(),
                    cidr: *network_cidr,
                    parent: None,
                },
            )
            .map_err(|_| anyhow!("failed to create root CIDR"))?;
            Ok(cidr)
        },
    }
}

fn ensure_server_cidr(
    conn: &Connection,
    cidrs: &mut Vec<shared::Cidr>,
    network_cidr: &IpNet,
    root_cidr_id: i64,
) -> Result<shared::Cidr, shared::Error> {
    let Some(our_ip) = network_cidr
        .hosts()
        .find(|ip| network_cidr.is_assignable(ip))
    else {
        bail!("no assignable IP found in network CIDR");
    };

    match cidrs.iter().position(|cidr| cidr.name == SERVER_NAME) {
        Some(cidr_index) => Ok(cidrs.swap_remove(cidr_index)),
        None => {
            let cidr = DatabaseCidr::create(
                conn,
                CidrContents {
                    name: SERVER_NAME.into(),
                    cidr: IpNet::new(our_ip, network_cidr.max_prefix_len())?,
                    parent: Some(root_cidr_id),
                },
            )
            .map_err(|_| anyhow!("failed to create innernet-server CIDR"))?;
            Ok(cidr)
        },
    }
}

fn ensure_server_peer(
    conn: &Connection,
    server_cidr: &shared::Cidr,
    external_endpoint: &Option<shared::Endpoint>,
    listen_port: u16,
) -> Result<(shared::Peer, Option<KeyPair>), shared::Error> {
    let peers = DatabasePeer::list(conn)?;

    let server_peer_name = SERVER_NAME.parse().map_err(|e: &str| anyhow!(e))?;

    match peers.into_iter().find(|peer| peer.name == server_peer_name) {
        None => {
            let endpoint: shared::Endpoint = if let Some(endpoint) = &external_endpoint {
                endpoint.clone()
            } else {
                let ip = publicip::get_any(Preference::Ipv4)
                    .ok_or_else(|| anyhow!("couldn't get external IP"))?;
                SocketAddr::new(ip, listen_port).into()
            };

            let our_keypair = KeyPair::generate();

            let peer = DatabasePeer::create(
                conn,
                PeerContents {
                    name: SERVER_NAME.parse().map_err(|e: &str| anyhow!(e))?,
                    ip: server_cidr.cidr.addr(),
                    cidr_id: server_cidr.id,
                    public_key: our_keypair.public.to_base64(),
                    endpoint: Some(endpoint),
                    is_admin: true,
                    is_disabled: false,
                    is_redeemed: true,
                    persistent_keepalive_interval: Some(PERSISTENT_KEEPALIVE_INTERVAL_SECS),
                    invite_expires: None,
                    candidates: vec![],
                },
            )
            .map_err(|_| anyhow!("failed to create innernet peer."))?;

            Ok((peer.inner, Some(our_keypair)))
        },
        Some(peer) => Ok((peer.inner, None)),
    }
}

fn get_available_ip_in_cidr(
    cidr: &shared::Cidr,
    peers: &[DatabasePeer],
) -> (Option<IpAddr>, Option<IpNet>) {
    let candidate_ips = cidr.hosts().filter(|ip| cidr.is_assignable(ip));
    let mut available_ip = None;
    for ip in candidate_ips {
        if !peers.iter().any(|peer| peer.ip == ip) {
            available_ip = Some(ip);
            break;
        }
    }
    let available_ip_net =
        available_ip.and_then(|ip| IpNet::new(ip, cidr.cidr.max_prefix_len()).ok());
    (available_ip, available_ip_net)
}

#[derive(Debug, Clone)]
pub struct Control {
    interface: InterfaceName,
    config: ConfigFile,
    network: NetworkOpts,
    db: Db,
}

impl Control {
    pub fn ensure_initialized(
        conf: &ServerConfig,
        opts: InitializeOpts,
    ) -> Result<Self, shared::Error> {
        shared::ensure_dirs_exist(&[conf.config_dir(), conf.database_dir()])
            .map_err(|_| anyhow!("Failed to create config and database directories",))?;

        let database_path = conf.database_path(&opts.network_name);
        let conn = match std::fs::metadata(&database_path) {
            Ok(_) => open_database_connection(&opts.network_name, conf)?,
            Err(_) => create_database(&database_path)
                .map_err(|_| anyhow!("failed to create database",))?,
        };

        let mut cidrs = DatabaseCidr::list(&conn)?;

        let root_cidr =
            ensure_root_cidr(&conn, &mut cidrs, &opts.network_name, &opts.network_cidr)?;

        let server_cidr = ensure_server_cidr(&conn, &mut cidrs, &opts.network_cidr, root_cidr.id)?;

        let (_server_peer, server_key) = ensure_server_peer(
            &conn,
            &server_cidr,
            &opts.external_endpoint,
            opts.listen_port,
        )?;

        let config_path = conf.config_path(&opts.network_name);

        let config = match server_key {
            None => ConfigFile::from_file(config_path)?,
            Some(key) => {
                let config = ConfigFile {
                    private_key: key.private.to_base64(),
                    listen_port: opts.listen_port,
                    address: server_cidr.cidr.addr(),
                    network_cidr_prefix: opts.network_cidr.prefix_len(),
                };

                config.write_to_path(config_path)?;
                config
            },
        };

        let backend = Backend::variants()
            .first()
            .and_then(|s| s.parse::<Backend>().ok())
            .ok_or_else(|| anyhow!("failed to select backend for wg"))?;

        let db = Arc::new(Mutex::new(conn));

        let network = NetworkOpts {
            no_routing: false,
            backend,
            mtu: None,
        };

        Ok(Self {
            interface: opts.network_name,
            config,
            network,
            db,
        })
    }

    pub fn add_peer(&self, edge_id: String) -> Result<InterfaceConfig, ServerError> {
        if edge_id == SERVER_NAME {
            return Err(ServerError::InvalidQuery);
        }

        let conn = self.db.lock();

        let cidrs = DatabaseCidr::list(&conn)?;
        let peers = DatabasePeer::list(&conn)?;

        let root_cidr = cidrs
            .iter()
            .find(|cidr| cidr.name == self.interface.to_string())
            .ok_or_else(|| ServerError::Internal(String::from("root cidr not found")))?;

        let (peer_ip, peer_ip_net) = match get_available_ip_in_cidr(root_cidr, &peers) {
            (Some(ip), Some(net)) => (ip, net),
            _ => {
                return Err(ServerError::Internal(String::from(
                    "couldn't construct peer ip and cidr in root cidr",
                )))
            },
        };

        let peer_name = edge_id
            .parse::<shared::Hostname>()
            .map_err(|_| ServerError::InvalidQuery)?;

        let peer_cidr = match cidrs.iter().find(|c| c.name == edge_id) {
            Some(c) => c,
            None => &DatabaseCidr::create(
                &conn,
                CidrContents {
                    name: edge_id,
                    cidr: peer_ip_net,
                    parent: Some(root_cidr.id),
                },
            )?,
        };

        let peer_keypair = KeyPair::generate();

        let peer_request = PeerContents {
            name: peer_name,
            ip: peer_ip,
            cidr_id: peer_cidr.id,
            public_key: peer_keypair.public.to_base64(),
            endpoint: None,
            is_admin: false,
            is_disabled: false,
            is_redeemed: false,
            persistent_keepalive_interval: Some(PERSISTENT_KEEPALIVE_INTERVAL_SECS),
            invite_expires: Some(SystemTime::now() + Duration::from_secs(15 * 60)),
            candidates: vec![],
        };

        let peer = DatabasePeer::create(&conn, peer_request)?;

        if cfg!(not(test)) && Device::get(&self.interface, self.network.backend).is_ok() {
            DeviceUpdate::new()
                .add_peer(PeerConfigBuilder::from(&*peer))
                .apply(&self.interface, self.network.backend)
                .map_err(|_| ServerError::WireGuard)?;
        }

        let server_peer_name = SERVER_NAME
            .parse()
            .map_err(|_| ServerError::Internal(String::from("should be a hostname")))?;
        let server_peer = peers
            .iter()
            .find(|peer| peer.name == server_peer_name)
            .ok_or_else(|| {
                ServerError::Internal(String::from("server peer must always be present"))
            })?;

        self.generate_peer_invitation(&cidrs, server_peer, &peer, &peer_keypair)
    }

    fn generate_peer_invitation(
        &self,
        cidrs: &[shared::Cidr],
        server_peer: &DatabasePeer,
        peer: &DatabasePeer,
        peer_keypair: &KeyPair,
    ) -> Result<InterfaceConfig, ServerError> {
        let cidr_tree = CidrTree::new(cidrs);

        let server_api_endpoint = &SocketAddr::new(self.config.address, self.config.listen_port);

        let peer_invitation = InterfaceConfig {
            interface: InterfaceInfo {
                network_name: self.interface.to_string(),
                private_key: peer_keypair.private.to_base64(),
                address: IpNet::new(peer.ip, cidr_tree.prefix_len()).map_err(|_| {
                    ServerError::Internal(String::from("couldn't construct cidr for invitation"))
                })?,
                listen_port: None,
            },
            server: ServerInfo {
                external_endpoint: server_peer.endpoint.clone().ok_or_else(|| {
                    ServerError::Internal(String::from(
                        "server peer should have a wireguard endpoint",
                    ))
                })?,
                internal_endpoint: *server_api_endpoint,
                public_key: server_peer.public_key.clone(),
            },
        };

        Ok(peer_invitation)
    }

    pub fn remove_peer(&self, edge_id: String) -> Result<(), ServerError> {
        if edge_id == SERVER_NAME {
            return Err(ServerError::InvalidQuery);
        }

        let name = edge_id
            .parse::<shared::Hostname>()
            .map_err(|_| ServerError::InvalidQuery)?;

        let conn = self.db.lock();

        let peer =
            DatabasePeer::get_from_name(&conn, name).map_err(|_| ServerError::NotFound)?;

        peer.delete(&conn)?;

        let public_key = Key::from_base64(&peer.public_key).map_err(|_| ServerError::WireGuard)?;
        DeviceUpdate::new()
            .remove_peer_by_key(&public_key)
            .apply(&self.interface, self.network.backend)
            .map_err(|_| ServerError::WireGuard)?;

        Ok(())
    }

    pub async fn serve(&self) -> Result<(), shared::Error> {
        let conn = self.db.lock();

        let mut peers = DatabasePeer::list(&conn)?;
        log::debug!("peers listed...");
        let peer_configs = peers
            .iter()
            .map(|peer| peer.deref().into())
            .collect::<Vec<PeerConfigBuilder>>();

        log::info!("bringing up interface.");
        wg::up(
            &self.interface,
            &self.config.private_key,
            IpNet::new(self.config.address, self.config.network_cidr_prefix)?,
            Some(self.config.listen_port),
            None,
            self.network,
        )?;

        DeviceUpdate::new()
            .add_peers(&peer_configs)
            .apply(&self.interface, self.network.backend)?;

        log::info!("{} peers added to wireguard interface.", peers.len());

        let candidates: Vec<shared::Endpoint> = get_local_addrs()?
            .map(|addr| SocketAddr::from((addr, self.config.listen_port)).into())
            .collect();
        let num_candidates = candidates.len();
        let myself = peers
            .iter_mut()
            .find(|peer| peer.ip == self.config.address)
            .expect("Couldn't find server peer in peer list.");
        myself.update(
            &conn,
            PeerContents {
                candidates,
                ..myself.contents.clone()
            },
        )?;
        drop(conn);

        log::info!(
            "{} local candidates added to server peer config.",
            num_candidates
        );

        let public_key =
            wireguard_control::Key::from_base64(&self.config.private_key)?.get_public();
        let endpoints = spawn_endpoint_refresher(self.interface, self.network);
        spawn_expired_invite_sweeper(self.db.clone());

        let context = Context {
            db: self.db.clone(),
            endpoints,
            interface: self.interface,
            public_key,
            backend: self.network.backend,
        };

        log::info!("innernet-server {} starting.", VERSION);

        let listener = get_listener(
            (self.config.address, self.config.listen_port).into(),
            &self.interface,
        )?;

        let make_svc = hyper::service::make_service_fn(move |socket: &AddrStream| {
            let remote_addr = socket.remote_addr();
            let context = context.clone();
            async move {
                Ok::<_, http::Error>(hyper::service::service_fn(move |req: Request<Body>| {
                    log::debug!("{} - {} {}", &remote_addr, req.method(), req.uri());
                    hyper_service(req, context.clone(), remote_addr)
                }))
            }
        });

        let server = hyper::Server::from_tcp(listener)?.serve(make_svc);

        server.await?;

        Ok(())
    }
}

fn spawn_endpoint_refresher(interface: InterfaceName, network: NetworkOpts) -> Endpoints {
    let endpoints = Arc::new(RwLock::new(HashMap::new()));
    tokio::task::spawn({
        let endpoints = endpoints.clone();
        async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            loop {
                interval.tick().await;
                if let Ok(info) = Device::get(&interface, network.backend) {
                    for peer in info.peers {
                        if let Some(endpoint) = peer.config.endpoint {
                            endpoints
                                .write()
                                .insert(peer.config.public_key.to_base64(), endpoint);
                        }
                    }
                }
            }
        }
    });
    endpoints
}

fn spawn_expired_invite_sweeper(db: Db) {
    tokio::task::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            match DatabasePeer::delete_expired_invites(&db.lock()) {
                Ok(deleted) if deleted > 0 => {
                    log::info!("Deleted {} expired peer invitations.", deleted)
                },
                Err(e) => log::error!("Failed to delete expired peer invitations: {}", e),
                _ => {},
            }
        }
    });
}

/// This function differs per OS, because different operating systems have
/// opposing characteristics when binding to a specific IP address.
/// On Linux, binding to a specific local IP address does *not* bind it to
/// that IP's interface, allowing for spoofing attacks.
///
/// See https://github.com/tonarino/innernet/issues/26 for more details.
#[cfg(target_os = "linux")]
fn get_listener(addr: SocketAddr, interface: &InterfaceName) -> Result<TcpListener, shared::Error> {
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    let sock = socket2::Socket::from(listener);
    sock.bind_device(Some(interface.as_str_lossy().as_bytes()))?;
    Ok(sock.into())
}

/// BSD-likes do seem to bind to an interface when binding to an IP,
/// according to the internet, but we may want to explicitly use
/// IP_BOUND_IF in the future regardless. This isn't currently in
/// the socket2 crate however, so we aren't currently using it.
///
/// See https://github.com/tonarino/innernet/issues/26 for more details.
#[cfg(not(target_os = "linux"))]
fn get_listener(addr: SocketAddr, _interface: &InterfaceName) -> Result<TcpListener, Error> {
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

pub(crate) async fn hyper_service(
    req: Request<Body>,
    context: Context,
    remote_addr: SocketAddr,
) -> Result<Response<Body>, http::Error> {
    // Break the path into components.
    let components: VecDeque<_> = req
        .uri()
        .path()
        .trim_start_matches('/')
        .split('/')
        .map(String::from)
        .collect();

    routes(req, context, remote_addr, components)
        .await
        .or_else(TryInto::try_into)
}

async fn routes(
    req: Request<Body>,
    context: Context,
    remote_addr: SocketAddr,
    mut components: VecDeque<String>,
) -> Result<Response<Body>, ServerError> {
    // Must be "/v1/[something]"
    if components.pop_front().as_deref() != Some("v1") {
        Err(ServerError::NotFound)
    } else {
        let session = get_session(&req, context, remote_addr.ip())?;
        let component = components.pop_front();
        match component.as_deref() {
            Some("user") => api::user::routes(req, components, session).await,
            _ => Err(ServerError::NotFound),
        }
    }
}

fn get_session(
    req: &Request<Body>,
    context: Context,
    addr: IpAddr,
) -> Result<Session, ServerError> {
    let pubkey = req
        .headers()
        .get(INNERNET_PUBKEY_HEADER)
        .ok_or(ServerError::Unauthorized)?;
    let pubkey = pubkey.to_str().map_err(|_| ServerError::Unauthorized)?;
    let pubkey = Key::from_base64(pubkey).map_err(|_| ServerError::Unauthorized)?;
    if pubkey
        .as_bytes()
        .ct_eq(context.public_key.as_bytes())
        .into()
    {
        let peer = DatabasePeer::get_from_ip(&context.db.lock(), addr).map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => ServerError::Unauthorized,
            e => ServerError::Database(e),
        })?;

        if !peer.is_disabled {
            return Ok(Session { context, peer });
        }
    }

    Err(ServerError::Unauthorized)
}
