use anyhow::Result;

use mvm_core::user_config::MvmConfig;

use super::*;

pub(super) trait TopLevelCommand {
    fn run(self, cli: &Cli, cfg: &MvmConfig) -> Result<()>;
    fn is_early_command(&self) -> bool;
    fn try_run_early(&self) -> Option<Result<()>>;
}

impl TopLevelCommand for Commands {
    fn run(self, cli: &Cli, cfg: &MvmConfig) -> Result<()> {
        match self {
            Commands::Env(a) => env::group::run(cli, a, cfg),
            Commands::Bootstrap(a) => bootstrap::run(cli, a, cfg),
            Commands::BuilderVmBootstrap(a) => bootstrap::run_builder_vm_bootstrap(cli, a, cfg),
            Commands::BuilderEgressSupervisor(a) => {
                bootstrap::run_builder_egress_supervisor(cli, a, cfg)
            }
            Commands::BuilderShellJob(a) => builder_shell_job::run(cli, a, cfg),
            Commands::Explain(a) => vm::explain::run(a),
            Commands::Why(a) => why::run(a),
            Commands::Run(a) => vm::exec::run_verb(cli, a, cfg),
            Commands::Bench(a) => bench::run(a),
            Commands::Plugin(a) => plugin::run(a),
            Commands::Completions(a) => completions::run(a),
            Commands::SdkNoVm(a) => vm::sdk_no_vm::run(&a),
            Commands::Doctor(a) => env::doctor::run(cli, a, cfg),
            Commands::Backend(a) => backend::run(cli, a, cfg),
            Commands::Dashboard(a) => dashboard::run(a),
            Commands::Prepare(a) => vm::prepare::run(a),
            Commands::Build(a) => build::front_door::run(cli, a, cfg),
            Commands::Dev(a) => build::group::run(cli, a, cfg),
            Commands::Deploy(a) => deploy::run(cli, a, cfg),
            Commands::Deployments(a) => deployments::run(cli, a, cfg),
            Commands::Kernel(a) => build::kernel::run(cli, a, cfg),
            Commands::Generate(a) => generate::run(cli, a, cfg),
            Commands::Template(a) => template::run(cli, a, cfg),
            Commands::Watch(a) => watch::run(cli, a, cfg),
            Commands::Manifest(a) => manifest::run(cli, a, cfg),
            Commands::Image(a) => image::run(cli, a, cfg),
            Commands::Pack(a) => pack::run(cli, a, cfg),
            Commands::Machine(a) => machine::run(cli, a, cfg),
            Commands::Storage(a) => storage::run(cli, a, cfg),
            Commands::ShellInit(a) => env::shell_init::run(cli, a, cfg),
            Commands::Ops(a) => ops::group::run(cli, a, cfg),
            Commands::Network(a) => ops::network::run(cli, a, cfg),
            Commands::Catalog(a) => catalog::run(cli, a, cfg),
            Commands::Cache(a) => ops::cache::run(cli, a, cfg),
            Commands::Pool(a) => pool::run(cli, a, cfg),
            Commands::Reconcile(a) => ops::reconcile::run(cli, a, cfg),
            Commands::Init(a) => env::init::run(cli, a, cfg),
            Commands::Secret(a) => ops::secret::run(cli, a, cfg),
            Commands::Bundle(a) => bundle::run(cli, a, cfg),
            Commands::Trust(a) => trust::run(cli, a, cfg),
            Commands::Policy(a) => policy::run(cli, a, cfg),
            Commands::Pull(a) => pull::run(cli, a, cfg),
            Commands::Search(a) => search::run(cli, a, cfg),
            Commands::AgentSession(a) => agent_session::run(cli, a, cfg),
            Commands::Deps(a) => deps::run(cli, a, cfg),
            Commands::Capture(a) => capture::run(cli, a, cfg),
            Commands::Artifact(a) => vm::artifact::run(cli, a, cfg),
            Commands::SeccompAudit(a) => seccomp_audit::run(cli, a),
            Commands::PersistentBuilder(a) => build::persistent_builder::run(cli, a),
            Commands::QemuVsockBridge(_) => {
                unreachable!("qemu vsock bridge short-circuits in run()")
            }
        }
    }

    fn is_early_command(&self) -> bool {
        // Uninstall runs before startup creates config, host signing keys and
        // the command audit envelope: it must not create the state directory
        // it is deciding whether to remove.
        // The archive-only reader likewise must not create keys or lifecycle
        // state while checking untrusted bytes.
        // Caller identity reads must stay side-effect free, and enrollment
        // creates only its explicit reservation and native credential.
        // `backend detect` is install.sh's probe of a just-extracted mvmctl:
        // it must answer without creating any state.
        matches!(
            self,
            Commands::QemuVsockBridge(_)
                | Commands::Backend(backend::Args {
                    action: backend::BackendCmd::Detect(_),
                    ..
                })
                | Commands::Dev(build::group::Args {
                    action: build::group::BuildCmd::GuestBins(build::guest_bins::Args {
                        check_release_archive: Some(_),
                        ..
                    }),
                    ..
                })
                | Commands::Env(env::group::Args {
                    action: env::group::EnvCmd::Uninstall(_),
                })
                | Commands::Env(env::group::Args {
                    action: env::group::EnvCmd::CallerIdentity(_),
                })
        )
    }

    fn try_run_early(&self) -> Option<Result<()>> {
        if !self.is_early_command() {
            return None;
        }
        match self {
            Commands::QemuVsockBridge(a) => Some(qemu_bridge::run(a)),
            Commands::Backend(backend::Args {
                action: backend::BackendCmd::Detect(args),
                ..
            }) => Some(backend::run_detect_early(args)),
            Commands::Dev(build::group::Args {
                action:
                    build::group::BuildCmd::GuestBins(build::guest_bins::Args {
                        check_release_archive: Some(archive),
                        ..
                    }),
                ..
            }) => Some(build::guest_bins::check_archive_to_stdout(archive)),
            Commands::Env(env::group::Args {
                action: env::group::EnvCmd::Uninstall(a),
            }) => Some(env::uninstall::run(a)),
            Commands::Env(env::group::Args {
                action: env::group::EnvCmd::CallerIdentity(a),
            }) => Some(env::caller_identity::run(a.clone())),
            _ => None,
        }
    }
}
