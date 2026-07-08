use mvm_net::guest_netd::{GuestNetdError, config_from_args_and_env, run_guest_netd, usage};

fn main() {
    let config = match config_from_args_and_env(std::env::args().skip(1), std::env::vars()) {
        Ok(config) => config,
        Err(GuestNetdError::HelpRequested) => {
            print!("{}", usage());
            return;
        }
        Err(err) => {
            eprintln!("mvm-guest-netd: {err}");
            std::process::exit(2);
        }
    };

    match run_guest_netd(config) {
        Ok(stats) => {
            eprintln!(
                "mvm-guest-netd: stopped after {} ticks, {} guest packets read, {} guest packets written",
                stats.ticks, stats.guest_packets_read, stats.guest_packets_written
            );
        }
        Err(err) => {
            eprintln!("mvm-guest-netd: {err}");
            std::process::exit(1);
        }
    }
}
