use super::Error;
use crate::{
    Repository,
    config::{cache::util::ApplyLeniency, tree::Pack},
};

pub fn index_threads(repo: &Repository) -> Result<Option<usize>, Error> {
    Ok(Pack::THREADS
        .try_into_usize(
            repo.config
                .resolved
                .integer_filter(Pack::THREADS, &mut repo.filter_config_section()),
        )
        .with_leniency(repo.options.lenient_config)?)
}

pub fn pack_index_version(repo: &Repository) -> Result<gix_pack::index::Version, Error> {
    Ok(Pack::INDEX_VERSION
        .try_into_index_version(repo.config.resolved.integer(Pack::INDEX_VERSION))
        .with_leniency(repo.options.lenient_config)?
        .unwrap_or(gix_pack::index::Version::V2))
}
