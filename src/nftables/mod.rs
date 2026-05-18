use log::warn;

use crate::nftables::config::NftConfig;

pub mod builder;
pub mod config;

pub fn flush_table(config: &NftConfig<'_>) {
    let _ = config.delete_table_and_apply().map_err(|e| {
        warn!(
            "the `{}` table (probably) already deleted: {}",
            config.table_name, e
        );
    });
}
