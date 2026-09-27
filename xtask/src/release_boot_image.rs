//! `xtask release-boot-image tag` — print the image-set tag this CLI embeds.
//!
//! Images are built and signed in `mvm-images`; a CLI release carries none of
//! them. What a workflow or operator still needs from this side is the one tag
//! the compiled lock pins, read through the same Rust constant the released
//! `mvmctl` embeds rather than parsed out of the lock a second way.

use anyhow::{Result, bail};

pub(crate) fn run(args: &[String]) -> Result<()> {
    match args {
        [cmd] if cmd == "tag" => {
            println!("{}", mvm_core::config::default_boot_image_tag());
            Ok(())
        }
        _ => bail!("usage: release-boot-image tag"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_is_the_only_subcommand() {
        assert!(run(&["tag".to_string()]).is_ok());
        for args in [
            vec![],
            vec!["mirror-assets".to_string()],
            vec!["validate".to_string(), "t".to_string(), "d".to_string()],
            vec!["tag".to_string(), "extra".to_string()],
        ] {
            let error = run(&args).expect_err("only `tag` is accepted").to_string();
            assert!(error.contains("usage: release-boot-image tag"), "{error}");
        }
    }
}
