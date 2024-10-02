use clap::{Args, Parser, Subcommand};
use innernet_client::{
    add_association, add_cidr, add_peer, delete_association, delete_cidr, enable_or_disable_peer,
    fetch, install, list_associations, list_cidrs, override_endpoint, rename_cidr, rename_peer,
    set_listen_port, show, uninstall, up, Opts,
    util,
};
use shared::{
    AddCidrOpts, AddDeleteAssociationOpts, AddPeerOpts, DeleteCidrOpts, EnableDisablePeerOpts,
    InstallOpts, Interface, ListenPortOpts, NatOpts, OverrideEndpointOpts, RenameCidrOpts,
    RenamePeerOpts, WrappedIoError,
};
use std::{io, path::PathBuf, time::Duration};

use shared::{wg, Error};

#[derive(Clone, Debug, Parser)]
#[command(name = "innernet", author, version, about)]
struct RunOpts {
    #[clap(subcommand)]
    command: Option<Command>,

    #[clap(flatten)]
    inner: Opts,
}

#[derive(Clone, Debug, Args)]
struct HostsOpt {
    /// The path to write hosts to
    #[clap(long = "hosts-path", default_value = "/etc/hosts")]
    hosts_path: PathBuf,

    /// Don't write to any hosts files
    #[clap(long = "no-write-hosts", conflicts_with = "hosts_path")]
    no_write_hosts: bool,
}

impl From<HostsOpt> for Option<PathBuf> {
    fn from(opt: HostsOpt) -> Self {
        (!opt.no_write_hosts).then_some(opt.hosts_path)
    }
}

#[derive(Clone, Debug, Subcommand)]
enum Command {
    /// Install a new innernet config
    #[clap(alias = "redeem")]
    Install {
        /// Path to the invitation file
        invite: PathBuf,

        #[clap(flatten)]
        hosts: HostsOpt,

        #[clap(flatten)]
        install_opts: InstallOpts,

        #[clap(flatten)]
        nat: NatOpts,
    },

    /// Enumerate all innernet connections
    #[clap(alias = "list")]
    Show {
        /// One-line peer list
        #[clap(short, long)]
        short: bool,

        /// Display peers in a tree based on the CIDRs
        #[clap(short, long)]
        tree: bool,

        interface: Option<Interface>,
    },

    /// Bring up your local interface, and update it with latest peer list
    Up {
        /// Enable daemon mode i.e. keep the process running, while fetching
        /// the latest peer list periodically
        #[clap(short, long)]
        daemon: bool,

        /// Keep fetching the latest peer list at the specified interval in
        /// seconds. Valid only in daemon mode
        #[clap(long, default_value = "60")]
        interval: u64,

        #[clap(flatten)]
        hosts: HostsOpt,

        #[clap(flatten)]
        nat: NatOpts,

        interface: Option<Interface>,
    },

    /// Fetch and update your local interface with the latest peer list
    Fetch {
        interface: Interface,

        #[clap(flatten)]
        hosts: HostsOpt,

        #[clap(flatten)]
        nat: NatOpts,
    },

    /// Uninstall an innernet network.
    Uninstall {
        interface: Interface,

        /// Bypass confirmation
        #[clap(long)]
        yes: bool,
    },

    /// Bring down the interface (equivalent to 'wg-quick down <interface>')
    Down { interface: Interface },

    /// Add a new peer
    ///
    /// By default, you'll be prompted interactively to create a peer, but you can
    /// also specify all the options in the command, eg:
    ///
    /// --name 'person' --cidr 'humans' --admin false --auto-ip --save-config 'person.toml' --yes
    AddPeer {
        interface: Interface,

        #[clap(flatten)]
        sub_opts: AddPeerOpts,
    },

    /// Rename a peer
    ///
    /// By default, you'll be prompted interactively to select a peer, but you can
    /// also specify all the options in the command, eg:
    ///
    /// --name 'person' --new-name 'human'
    RenamePeer {
        interface: Interface,

        #[clap(flatten)]
        sub_opts: RenamePeerOpts,
    },

    /// Add a new CIDR
    AddCidr {
        interface: Interface,

        #[clap(flatten)]
        sub_opts: AddCidrOpts,
    },

    /// Rename a CIDR
    ///
    /// By default, you'll be prompted interactively to select a CIDR, but you can
    /// also specify all the options in the command, eg:
    ///
    /// --name 'group' --new-name 'family'
    RenameCidr {
        interface: Interface,

        #[clap(flatten)]
        sub_opts: RenameCidrOpts,
    },

    /// Delete a CIDR
    DeleteCidr {
        interface: Interface,

        #[clap(flatten)]
        sub_opts: DeleteCidrOpts,
    },

    /// List CIDRs
    ListCidrs {
        interface: Interface,

        /// Display CIDRs in tree format
        #[clap(short, long)]
        tree: bool,
    },

    /// Disable an enabled peer
    DisablePeer {
        interface: Interface,

        #[clap(flatten)]
        sub_opts: EnableDisablePeerOpts,
    },

    /// Enable a disabled peer
    EnablePeer {
        interface: Interface,

        #[clap(flatten)]
        sub_opts: EnableDisablePeerOpts,
    },

    /// Add an association between CIDRs
    AddAssociation {
        interface: Interface,

        #[clap(flatten)]
        sub_opts: AddDeleteAssociationOpts,
    },

    /// Delete an association between CIDRs
    DeleteAssociation {
        interface: Interface,

        #[clap(flatten)]
        sub_opts: AddDeleteAssociationOpts,
    },

    /// List existing assocations between CIDRs
    ListAssociations { interface: Interface },

    /// Set the local listen port.
    SetListenPort {
        interface: Interface,

        #[clap(flatten)]
        sub_opts: ListenPortOpts,
    },

    /// Override your external endpoint that the server sends to other peers
    OverrideEndpoint {
        interface: Interface,

        #[clap(flatten)]
        sub_opts: OverrideEndpointOpts,
    },

    /// Generate shell completion scripts
    Completions {
        #[clap(value_enum)]
        shell: clap_complete::Shell,
    },
}

fn main() {
    let opts = RunOpts::parse();
    util::init_logger(opts.inner.verbose);

    if let Err(e) = run(&opts.command, &opts.inner) {
        println!();
        log::error!("{}\n", e);
        if let Some(e) = e.downcast_ref::<WrappedIoError>() {
            util::permissions_helptext(&opts.inner.config_dir, &opts.inner.data_dir, e);
        }
        if let Some(e) = e.downcast_ref::<io::Error>() {
            util::permissions_helptext(&opts.inner.config_dir, &opts.inner.data_dir, e);
        }
        std::process::exit(1);
    }
}

fn run(command: &Option<Command>, opts: &Opts) -> Result<(), Error> {
    let command = command.clone().unwrap_or(Command::Show {
        short: false,
        tree: false,
        interface: None,
    });

    match command {
        Command::Install {
            invite,
            hosts,
            install_opts,
            nat,
        } => install(opts, &invite, hosts.into(), install_opts, &nat)?,
        Command::Show {
            short,
            tree,
            interface,
        } => show(opts, short, tree, interface)?,
        Command::Fetch {
            interface,
            hosts,
            nat,
        } => fetch(&interface, opts, false, hosts.into(), &nat)?,
        Command::Up {
            interface,
            daemon,
            hosts,
            nat,
            interval,
        } => up(
            interface,
            opts,
            daemon.then(|| Duration::from_secs(interval)),
            hosts.into(),
            &nat,
        )?,
        Command::Down { interface } => wg::down(&interface, opts.network.backend)?,
        Command::Uninstall { interface, yes } => uninstall(&interface, opts, yes)?,
        Command::AddPeer {
            interface,
            sub_opts,
        } => add_peer(&interface, opts, sub_opts)?,
        Command::RenamePeer {
            interface,
            sub_opts,
        } => rename_peer(&interface, opts, sub_opts)?,
        Command::AddCidr {
            interface,
            sub_opts,
        } => add_cidr(&interface, opts, sub_opts)?,
        Command::RenameCidr {
            interface,
            sub_opts,
        } => rename_cidr(&interface, opts, sub_opts)?,
        Command::DeleteCidr {
            interface,
            sub_opts,
        } => delete_cidr(&interface, opts, sub_opts)?,
        Command::ListCidrs { interface, tree } => list_cidrs(&interface, opts, tree)?,
        Command::DisablePeer {
            interface,
            sub_opts,
        } => enable_or_disable_peer(&interface, opts, sub_opts, false)?,
        Command::EnablePeer {
            interface,
            sub_opts,
        } => enable_or_disable_peer(&interface, opts, sub_opts, true)?,
        Command::AddAssociation {
            interface,
            sub_opts,
        } => add_association(&interface, opts, sub_opts)?,
        Command::DeleteAssociation {
            interface,
            sub_opts,
        } => delete_association(&interface, opts, sub_opts)?,
        Command::ListAssociations { interface } => list_associations(&interface, opts)?,
        Command::SetListenPort {
            interface,
            sub_opts,
        } => {
            set_listen_port(&interface, opts, sub_opts)?;
        },
        Command::OverrideEndpoint {
            interface,
            sub_opts,
        } => {
            override_endpoint(&interface, opts, sub_opts)?;
        },
        Command::Completions { shell } => {
            use clap::CommandFactory;
            let mut app = RunOpts::command();
            let app_name = app.get_name().to_string();
            clap_complete::generate(shell, &mut app, app_name, &mut std::io::stdout());
            std::process::exit(0);
        },
    }

    Ok(())
}
