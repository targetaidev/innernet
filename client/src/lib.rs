use anyhow::{anyhow, bail};
use colored::*;
use data_store::DataStore;
use hostsfile::HostsBuilder;
use nat::NatTraverse;
use shared::{
    get_local_addrs, prompts, wg::DeviceExt, Endpoint, EndpointContents, IoErrorContext,
    ListenPortOpts, NatOpts, NetworkOpts, OverrideEndpointOpts, Peer, RedeemContents, State,
    WrappedIoError, REDEEM_TRANSITION_WAIT,
};
use shared::{wg, Error};
use std::{
    net::SocketAddr,
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};
use util::Api;
use wireguard_control::{Backend, Device, DeviceUpdate, PeerConfigBuilder};

mod data_store;
mod nat;
pub mod util;

pub use shared::interface_config::{InterfaceConfig, InterfaceInfo, ServerInfo};
pub use wireguard_control::InterfaceName;

fn update_hosts_file(
    interface: &InterfaceName,
    hosts_path: PathBuf,
    peers: &[Peer],
) -> Result<(), WrappedIoError> {
    let mut hosts_builder = HostsBuilder::new(format!("innernet {interface}"));
    for peer in peers {
        hosts_builder.add_hostname(
            peer.contents.ip,
            format!("{}.{}.wg", peer.contents.name, interface),
        );
    }
    match hosts_builder.write_to(&hosts_path).with_path(&hosts_path) {
        Ok(has_written) if has_written => {
            log::info!(
                "updated {} with the latest peers.",
                hosts_path.to_string_lossy().yellow()
            )
        },
        Ok(_) => {},
        Err(e) => log::warn!("failed to update hosts ({})", e),
    };

    Ok(())
}

#[derive(Debug)]
pub struct ClientConfig {
    pub hosts_path: Option<PathBuf>,
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
}

#[derive(Debug)]
pub struct Control {
    interface: InterfaceName,
    client_config: ClientConfig,
    network: NetworkOpts,
    nat: NatOpts,
}

pub trait Controllable {
    fn up(&self) -> Result<(), Error>;
    fn install(&self, config: InterfaceConfig) -> Result<(), Error>;
    fn uninstall(&self) -> Result<(), Error>;
}

impl Control {
    pub fn new(client_config: ClientConfig, interface: InterfaceName) -> Result<Self, Error> {
        shared::ensure_dirs_exist(&[&client_config.config_dir])?;

        let backend = Backend::variants()
            .first()
            .and_then(|s| s.parse::<Backend>().ok())
            .ok_or_else(|| anyhow!("failed to select backend for wg"))?;

        let network = NetworkOpts {
            no_routing: false,
            backend,
            mtu: None,
        };

        let nat = NatOpts {
            no_nat_traversal: false,
            exclude_nat_candidates: Vec::with_capacity(0),
            no_nat_candidates: false,
        };

        Ok(Self {
            interface,
            client_config,
            network,
            nat,
        })
    }

    pub fn set_listen_port(&self, sub_opts: ListenPortOpts) -> Result<Option<u16>, Error> {
        let mut config =
            InterfaceConfig::from_interface(&self.client_config.config_dir, &self.interface)?;

        let listen_port = prompts::set_listen_port(&config.interface, sub_opts)?;
        if let Some(listen_port) = listen_port {
            wg::set_listen_port(&self.interface, listen_port, self.network.backend)?;
            log::info!("the interface is updated");

            config.interface.listen_port = listen_port;
            config.write_to_interface(&self.client_config.config_dir, &self.interface)?;
            log::info!("the config file is updated");
        } else {
            log::info!("exiting without updating the listen port.");
        }

        Ok(listen_port.flatten())
    }

    pub fn override_endpoint(&self, sub_opts: OverrideEndpointOpts) -> Result<(), Error> {
        let config =
            InterfaceConfig::from_interface(&self.client_config.config_dir, &self.interface)?;

        let endpoint_contents = if sub_opts.unset {
            prompts::unset_override_endpoint(&sub_opts)?.then_some(EndpointContents::Unset)
        } else {
            let port = match config.interface.listen_port {
                Some(port) => port,
                None => bail!("you need to set a listen port with set-listen-port before overriding the endpoint (otherwise port randomization on the interface would make it useless).")
            };
            let endpoint = prompts::override_endpoint(&sub_opts, port)?;
            endpoint.map(EndpointContents::Set)
        };

        if let Some(contents) = endpoint_contents {
            log::info!("requesting endpoint update...");
            Api::new(&config.server).http_form::<_, ()>("PUT", "/user/endpoint", contents)?;
            log::info!(
                "endpoint override {}",
                if sub_opts.unset { "unset" } else { "set" }
            );
        } else {
            log::info!("exiting without overriding endpoint");
        }

        Ok(())
    }
}

impl Controllable for Control {
    fn install(&self, config: InterfaceConfig) -> Result<(), Error> {
        if config.interface.network_name != self.interface.to_string() {
            bail!(
                "Expected interface's network name to equal \"{}\".",
                &self.interface
            );
        }

        let target_conf = self
            .client_config
            .config_dir
            .join(self.interface.to_string())
            .with_extension("conf");
        if target_conf.exists() {
            bail!(
                "An existing innernet network with the name \"{}\" already exists.",
                &self.interface
            );
        }
        if Device::list(self.network.backend)
            .iter()
            .flatten()
            .any(|name| name == &self.interface)
        {
            bail!(
                "An existing WireGuard interface with the name \"{}\" already exists.",
                &self.interface
            );
        }

        redeem_invite(&self.interface, config, target_conf, self.network).map_err(|e| {
            log::error!("failed to start the interface: {}.", e);
            log::info!("bringing down the interface.");
            if let Err(e) = wg::down(&self.interface, self.network.backend) {
                log::warn!("failed to bring down interface: {}.", e.to_string());
            };
            log::error!("Failed to redeem invite. Now's a good time to make sure the server is started and accessible!");
            e
        })?;

        let mut up_success = false;
        for _ in 0..3 {
            if self.up().is_ok() {
                up_success = true;
                break;
            }
            thread::sleep(Duration::from_secs(1));
        }
        if !up_success {
            log::warn!(
                "Failed to fetch peers from server, you will need to manually run the 'up' command.",
            );
        }

        Ok(())
    }

    fn up(&self) -> Result<(), Error> {
        let config =
            InterfaceConfig::from_interface(&self.client_config.config_dir, &self.interface)?;
        let interface_up = match Device::list(self.network.backend) {
            Ok(interfaces) => interfaces.iter().any(|name| name == &self.interface),
            _ => false,
        };
        if !interface_up {
            log::info!(
                "bringing up interface {}.",
                &self.interface.as_str_lossy().yellow()
            );
            let resolved_endpoint = config
                .server
                .external_endpoint
                .resolve()
                .with_str(config.server.external_endpoint.to_string())?;
            wg::up(
                &self.interface,
                &config.interface.private_key,
                config.interface.address,
                config.interface.listen_port,
                Some((
                    &config.server.public_key,
                    config.server.internal_endpoint.ip(),
                    resolved_endpoint,
                )),
                self.network,
            )
            .with_str(self.interface.to_string())?;
        }

        log::info!(
            "fetching state for {} from server...",
            &self.interface.as_str_lossy().yellow()
        );
        let mut store = DataStore::open_or_create(&self.client_config.data_dir, &self.interface)?;
        let api = Api::new(&config.server);
        let State { peers, cidrs } = api.http("GET", "/user/state")?;

        let device = Device::get(&self.interface, self.network.backend)?;
        let modifications = device.diff(&peers);

        let updates = modifications
            .iter()
            .inspect(|diff| util::print_peer_diff(&store, diff))
            .cloned()
            .map(PeerConfigBuilder::from)
            .collect::<Vec<_>>();

        if !updates.is_empty() || !interface_up {
            DeviceUpdate::new()
                .add_peers(&updates)
                .apply(&self.interface, self.network.backend)
                .with_str(self.interface.to_string())?;

            if let Some(path) = self.client_config.hosts_path.clone() {
                update_hosts_file(&self.interface, path, &peers)?;
            }

            println!();
            log::info!(
                "updated interface {}\n",
                &self.interface.as_str_lossy().yellow()
            );
        } else {
            log::info!("{}", "peers are already up to date".green());
        }
        let interface_updated_time = Instant::now();

        store.set_cidrs(cidrs);
        store.update_peers(&peers)?;
        store.write().with_str(self.interface.to_string())?;

        let candidates: Vec<Endpoint> = get_local_addrs()?
            .filter(|ip| !self.nat.is_excluded(*ip))
            .map(|addr| SocketAddr::from((addr, device.listen_port.unwrap_or(51820))).into())
            .collect::<Vec<Endpoint>>();
        log::info!(
            "reporting {} interface address{} as NAT traversal candidates",
            candidates.len(),
            if candidates.len() == 1 { "" } else { "es" },
        );
        for candidate in &candidates {
            log::debug!("  candidate: {}", candidate);
        }
        match api.http_form::<_, ()>("PUT", "/user/candidates", &candidates) {
            Err(ureq::Error::Status(404, _)) => {
                log::warn!("your network is using an old version of innernet-server that doesn't support NAT traversal candidate reporting.")
            },
            Err(e) => return Err(e.into()),
            _ => {},
        }
        log::debug!("candidates successfully reported");

        if self.nat.no_nat_traversal {
            log::debug!("NAT traversal explicitly disabled, not attempting.");
        } else {
            let mut nat_traverse =
                NatTraverse::new(&self.interface, self.network.backend, &modifications)?;

            // Give time for handshakes with recently changed endpoints to complete before attempting traversal.
            if !nat_traverse.is_finished() {
                thread::sleep(nat::STEP_INTERVAL - interface_updated_time.elapsed());
            }
            loop {
                if nat_traverse.is_finished() {
                    break;
                }
                log::info!(
                    "Attempting to establish connection with {} remaining unconnected peers...",
                    nat_traverse.remaining()
                );
                nat_traverse.step()?;
            }
        }

        Ok(())
    }

    fn uninstall(&self) -> Result<(), Error> {
        let config = InterfaceConfig::get_path(&self.client_config.config_dir, &self.interface);
        let data = DataStore::get_path(&self.client_config.data_dir, &self.interface);

        if !config.exists() && !data.exists() {
            bail!(
                "No network named \"{}\" exists.",
                &self.interface.as_str_lossy().yellow()
            );
        }

        log::info!("bringing down interface (if up).");
        wg::down(&self.interface, self.network.backend).ok();
        std::fs::remove_file(&config)
            .with_path(&config)
            .map_err(|e| log::warn!("{}", e.to_string().yellow()))
            .ok();
        std::fs::remove_file(&data)
            .with_path(&data)
            .map_err(|e| log::warn!("{}", e.to_string().yellow()))
            .ok();
        log::info!(
            "network {} is uninstalled.",
            &self.interface.as_str_lossy().yellow()
        );
        Ok(())
    }
}

fn redeem_invite(
    iface: &InterfaceName,
    mut config: InterfaceConfig,
    target_conf: PathBuf,
    network: NetworkOpts,
) -> Result<(), Error> {
    log::info!("bringing up interface {}.", iface.as_str_lossy().yellow());
    let resolved_endpoint = config
        .server
        .external_endpoint
        .resolve()
        .with_str(config.server.external_endpoint.to_string())?;
    wg::up(
        iface,
        &config.interface.private_key,
        config.interface.address,
        None,
        Some((
            &config.server.public_key,
            config.server.internal_endpoint.ip(),
            resolved_endpoint,
        )),
        network,
    )
    .with_str(iface.to_string())?;

    log::info!("Generating new keypair.");
    let keypair = wireguard_control::KeyPair::generate();

    log::info!(
        "Registering keypair with server (at {}).",
        &config.server.internal_endpoint
    );
    Api::new(&config.server).http_form::<_, ()>(
        "POST",
        "/user/redeem",
        RedeemContents {
            public_key: keypair.public.to_base64(),
        },
    )?;

    config.interface.private_key = keypair.private.to_base64();
    config.write_to_path(&target_conf, false, Some(0o600))?;
    log::info!(
        "New keypair registered. Copied config to {}.\n",
        target_conf.to_string_lossy().yellow()
    );

    log::info!("Changing keys and waiting 5s for server's WireGuard interface to transition.",);
    DeviceUpdate::new()
        .set_private_key(keypair.private)
        .apply(iface, network.backend)
        .with_str(iface.to_string())?;
    thread::sleep(REDEEM_TRANSITION_WAIT);

    Ok(())
}
