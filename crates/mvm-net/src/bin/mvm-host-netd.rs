use mvm_net::host_netd::{
    HostNetdError, launch_config_from_args_and_env, load_config_file, run_host_netd_stdio, usage,
};

fn main() {
    let launch = match launch_config_from_args_and_env(std::env::args().skip(1), std::env::vars()) {
        Ok(config) => config,
        Err(HostNetdError::HelpRequested) => {
            print!("{}", usage());
            return;
        }
        Err(err) => {
            eprintln!("mvm-host-netd: {err}");
            std::process::exit(2);
        }
    };

    let config = match load_config_file(launch.config_path()) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("mvm-host-netd: {err}");
            std::process::exit(2);
        }
    };

    match run_host_netd_stdio(&config) {
        Ok(stats) => {
            eprintln!(
                "mvm-host-netd: stopped after {} messages read, {} messages written",
                stats.messages_read, stats.messages_written
            );
        }
        Err(err) => {
            eprintln!("mvm-host-netd: {err}");
            std::process::exit(1);
        }
    }
}
