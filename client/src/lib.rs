use anyhow::{anyhow, bail};
use colored::*;
use hostsfile::HostsBuilder;
use shared::{
    get_local_addrs,
    interface_config::InterfaceConfig,
    prompts,
    wg::{DeviceExt, PeerInfoExt},
    CidrTree, Endpoint, EndpointContents, Interface, IoErrorContext, ListenPortOpts, NatOpts,
    NetworkOpts, OverrideEndpointOpts, Peer, RedeemContents, State, WrappedIoError,
    REDEEM_TRANSITION_WAIT,
};
use std::{
    io,
    net::SocketAddr,
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};
use wireguard_control::{Device, DeviceUpdate, InterfaceName, PeerConfigBuilder, PeerInfo};

mod data_store;
mod nat;
pub mod util;

use data_store::DataStore;
use nat::NatTraverse;
use shared::{wg, Error};
use util::{human_duration, human_size, Api};

struct PeerState<'a> {
    peer: &'a Peer,
    info: Option<&'a PeerInfo>,
}

macro_rules! println_pad {
    ($pad:expr, $($arg:tt)*) => {
        print!("{:pad$}", "", pad = $pad);
        println!($($arg)*);
    }
}

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
    /// The path to write hosts to
    //#[clap(long = "hosts-path", default_value = "/etc/hosts")]
    pub hosts_path: Option<PathBuf>,

    //#[clap(short, long, default_value = "/etc/innernet")]
    pub config_dir: PathBuf,

    //#[clap(short, long, default_value = "/var/lib/innernet")]
    pub data_dir: PathBuf,
}

#[derive(Debug)]
pub struct Control {
    conf: ClientConfig,
    network: NetworkOpts,
    nat: NatOpts,
}

impl Control {
    pub fn new(conf: ClientConfig, network: NetworkOpts, nat: NatOpts) -> Result<Self, Error> {
        shared::ensure_dirs_exist(&[&conf.config_dir])?;

        Ok(Self { conf, network, nat })
    }

    pub fn install(&self, config: InterfaceConfig) -> Result<(), Error> {
        let iface = config.interface.network_name.clone();
        let target_conf = self.conf.config_dir.join(&iface).with_extension("conf");
        if target_conf.exists() {
            bail!(
                "An existing innernet network with the name \"{}\" already exists.",
                iface
            );
        }
        let iface = iface.parse()?;
        if Device::list(self.network.backend)
            .iter()
            .flatten()
            .any(|name| name == &iface)
        {
            bail!(
                "An existing WireGuard interface with the name \"{}\" already exists.",
                iface
            );
        }
        redeem_invite(&iface, config, target_conf, self.network).map_err(|e| {
            log::error!("failed to start the interface: {}.", e);
            log::info!("bringing down the interface.");
            if let Err(e) = wg::down(&iface, self.network.backend) {
                log::warn!("failed to bring down interface: {}.", e.to_string());
            };
            log::error!("Failed to redeem invite. Now's a good time to make sure the server is started and accessible!");
            e
        })?;

        let mut up_success = false;
        for _ in 0..3 {
            if self.fetch(&iface).is_ok() {
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

    pub fn up(
        &self,
        interface: &InterfaceName,
        loop_interval: Option<Duration>,
    ) -> Result<(), Error> {
        loop {
            self.fetch(interface)?;

            match loop_interval {
                Some(interval) => thread::sleep(interval),
                None => break,
            }
        }

        Ok(())
    }

    fn fetch(&self, interface: &InterfaceName) -> Result<(), Error> {
        let config = InterfaceConfig::from_interface(&self.conf.config_dir, interface)?;
        let interface_up = match Device::list(self.network.backend) {
            Ok(interfaces) => interfaces.iter().any(|name| name == interface),
            _ => false,
        };
        if !interface_up {
            log::info!(
                "bringing up interface {}.",
                interface.as_str_lossy().yellow()
            );
            let resolved_endpoint = config
                .server
                .external_endpoint
                .resolve()
                .with_str(config.server.external_endpoint.to_string())?;
            wg::up(
                interface,
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
            .with_str(interface.to_string())?;
        }

        log::info!(
            "fetching state for {} from server...",
            interface.as_str_lossy().yellow()
        );
        let mut store = DataStore::open_or_create(&self.conf.data_dir, interface)?;
        let api = Api::new(&config.server);
        let State { peers, cidrs } = api.http("GET", "/user/state")?;

        let device = Device::get(interface, self.network.backend)?;
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
                .apply(interface, self.network.backend)
                .with_str(interface.to_string())?;

            if let Some(path) = self.conf.hosts_path.clone() {
                update_hosts_file(interface, path, &peers)?;
            }

            println!();
            log::info!("updated interface {}\n", interface.as_str_lossy().yellow());
        } else {
            log::info!("{}", "peers are already up to date".green());
        }
        let interface_updated_time = Instant::now();

        store.set_cidrs(cidrs);
        store.update_peers(&peers)?;
        store.write().with_str(interface.to_string())?;

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
                NatTraverse::new(interface, self.network.backend, &modifications)?;

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

    pub fn uninstall(&self, interface: &InterfaceName) -> Result<(), Error> {
        let config = InterfaceConfig::get_path(&self.conf.config_dir, interface);
        let data = DataStore::get_path(&self.conf.data_dir, interface);

        if !config.exists() && !data.exists() {
            bail!(
                "No network named \"{}\" exists.",
                interface.as_str_lossy().yellow()
            );
        }

        log::info!("bringing down interface (if up).");
        wg::down(interface, self.network.backend).ok();
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
            interface.as_str_lossy().yellow()
        );
        Ok(())
    }

    pub fn set_listen_port(
        &self,
        interface: &InterfaceName,
        sub_opts: ListenPortOpts,
    ) -> Result<Option<u16>, Error> {
        let mut config = InterfaceConfig::from_interface(&self.conf.config_dir, interface)?;

        let listen_port = prompts::set_listen_port(&config.interface, sub_opts)?;
        if let Some(listen_port) = listen_port {
            wg::set_listen_port(interface, listen_port, self.network.backend)?;
            log::info!("the interface is updated");

            config.interface.listen_port = listen_port;
            config.write_to_interface(&self.conf.config_dir, interface)?;
            log::info!("the config file is updated");
        } else {
            log::info!("exiting without updating the listen port.");
        }

        Ok(listen_port.flatten())
    }

    pub fn override_endpoint(
        &self,
        interface: &InterfaceName,
        sub_opts: OverrideEndpointOpts,
    ) -> Result<(), Error> {
        let config = InterfaceConfig::from_interface(&self.conf.config_dir, interface)?;

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

    pub fn show(&self, short: bool, tree: bool, interface: Option<Interface>) -> Result<(), Error> {
        let interfaces = interface.map_or_else(
            || Device::list(self.network.backend),
            |interface| Ok(vec![*interface]),
        )?;

        let devices = interfaces
            .into_iter()
            .filter_map(|name| {
                match DataStore::open(&self.conf.data_dir, &name) {
                    Ok(store) => {
                        let device =
                            Device::get(&name, self.network.backend).with_str(name.as_str_lossy());
                        Some(device.map(|device| (device, store)))
                    },
                    // Skip WireGuard interfaces that aren't managed by innernet.
                    Err(e) if e.kind() == io::ErrorKind::NotFound => None,
                    // Error on interfaces that *are* managed by innernet but are not readable.
                    Err(e) => Some(Err(e)),
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        if devices.is_empty() {
            log::info!("No innernet networks currently running.");
            return Ok(());
        }

        for (device_info, store) in devices {
            let public_key = match &device_info.public_key {
                Some(key) => key.to_base64(),
                None => {
                    log::warn!(
                        "network {} is missing public key.",
                        device_info.name.to_string().yellow()
                    );
                    continue;
                },
            };

            let peers = store.peers();
            let cidrs = store.cidrs();
            let me = peers
                .iter()
                .find(|p| p.public_key == public_key)
                .ok_or_else(|| anyhow!("missing peer info"))?;

            let mut peer_states = device_info
                .peers
                .iter()
                .map(|info| {
                    let public_key = info.config.public_key.to_base64();
                    match peers.iter().find(|p| p.public_key == public_key) {
                        Some(peer) => Ok(PeerState {
                            peer,
                            info: Some(info),
                        }),
                        None => Err(anyhow!("peer {} isn't an innernet peer.", public_key)),
                    }
                })
                .collect::<Result<Vec<PeerState>, _>>()?;
            peer_states.push(PeerState {
                peer: me,
                info: None,
            });

            print_interface(&device_info, short || tree)?;
            peer_states.sort_by_key(|peer| peer.peer.ip);

            if tree {
                let cidr_tree = CidrTree::new(cidrs);
                print_tree(&cidr_tree, &peer_states, 1);
            } else {
                for peer_state in peer_states {
                    print_peer(&peer_state, short, 1);
                }
            }
        }
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

fn print_tree(cidr: &CidrTree, peers: &[PeerState], level: usize) {
    println_pad!(
        level * 2,
        "{} {}",
        cidr.cidr.to_string().bold().blue(),
        cidr.name.blue(),
    );

    let mut children: Vec<_> = cidr.children().collect();
    children.sort();
    children
        .iter()
        .for_each(|child| print_tree(child, peers, level + 1));

    for peer in peers.iter().filter(|p| p.peer.cidr_id == cidr.id) {
        print_peer(peer, true, level);
    }
}

fn print_interface(device_info: &Device, short: bool) -> Result<(), Error> {
    if short {
        let listen_port_str = device_info
            .listen_port
            .map(|p| format!("(:{p}) "))
            .unwrap_or_default();
        println!(
            "{} {}",
            device_info.name.to_string().green().bold(),
            listen_port_str.dimmed(),
        );
    } else {
        println!(
            "{}: {}",
            "network".green().bold(),
            device_info.name.to_string().green(),
        );
        if let Some(listen_port) = device_info.listen_port {
            println!("  {}: {}", "listening port".bold(), listen_port);
        }
    }
    Ok(())
}

fn print_peer(peer: &PeerState, short: bool, level: usize) {
    let pad = level * 2;
    let PeerState { peer, info } = peer;
    if short {
        let connected = info
            .map(|info| info.is_recently_connected())
            .unwrap_or_default();

        let is_you = info.is_none();

        println_pad!(
            pad,
            "| {} {}: {} ({}{}…)",
            if connected || is_you {
                "◉".bold()
            } else {
                "◯".dimmed()
            },
            peer.ip.to_string().yellow().bold(),
            peer.name.yellow(),
            if is_you { "you, " } else { "" },
            &peer.public_key[..6].dimmed(),
        );
    } else {
        println_pad!(
            pad,
            "{}: {} ({}...)",
            "peer".yellow().bold(),
            peer.name.yellow(),
            &peer.public_key[..10].yellow(),
        );
        println_pad!(pad, "  {}: {}", "ip".bold(), peer.ip);
        if let Some(info) = info {
            if let Some(endpoint) = info.config.endpoint {
                println_pad!(pad, "  {}: {}", "endpoint".bold(), endpoint);
            }
            if let Some(last_handshake) = info.stats.last_handshake_time {
                let duration = last_handshake.elapsed().expect("horrible clock problem");
                println_pad!(
                    pad,
                    "  {}: {}",
                    "last handshake".bold(),
                    human_duration(duration),
                );
            }
            if info.stats.tx_bytes > 0 || info.stats.rx_bytes > 0 {
                println_pad!(
                    pad,
                    "  {}: {} received, {} sent",
                    "transfer".bold(),
                    human_size(info.stats.rx_bytes),
                    human_size(info.stats.tx_bytes),
                );
            }
        }
    }
}
