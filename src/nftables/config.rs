use crate::error::AppError;
use crate::nftables::builder::{NftRulesetBuilder, RuleDirection, RuleProto, SetElements};
use crate::set::custom_set::CustomSet;
use crate::utils::read_ip_set_file;
use crate::utils::subnet::parse_from_string;
use nftables::helper;
use nftables::schema::{Nftables, SetType};
use nftables::stmt::Statement;
use nftables::types::NfHook;
use std::env;
use nftnl::{Batch, ProtoFamily, Table};
use tracing::{debug, info};

/// Defines the configuration structure for managing `nftables`.
/// This includes tables, chains, sets, and rules used for blocking traffic.
pub struct NftConfig<'a> {
    /// Name of the table to contain the blocklist.
    pub table_name: String,
    /// Name of the `prerouting` chain used for ingress traffic.
    pub prerouting_chain: String,
    /// Name of the `postrouting` chain used for egress traffic.
    pub postrouting_chain: String,
    /// Name of the blocklist set for IPs.
    pub blocklist_set_name: String,
    pub anti_lockout_set: CustomSet<'a>,
    pub custom_blocklist_set: CustomSet<'a>,
}

impl<'a> NftConfig<'a> {
    /// Creates a new `NftConfig` by fetching configuration values from environment variables.
    ///
    /// # Returns
    /// A populated `NftConfig` instance with default values for unspecified environment variables.
    ///
    /// # Errors
    /// Returns an `AppError` if anti-lockout rules fail to load/parse.
    pub fn new(delimiter: Option<&str>) -> Result<Self, AppError> {
        let anti_lockout_set = CustomSet::new(
            env::var("NFTBLOCKD_ANTI_LOCKOUT_SET_NAME").unwrap_or("anti_lockout_set".to_string()),
            parse_from_string(env::var("NFTBLOCKD_ANTI_LOCKOUT_IPV4").ok().as_ref(), None),
            parse_from_string(env::var("NFTBLOCKD_ANTI_LOCKOUT_IPV6").ok().as_ref(), None),
        )?;

        let custom_blocklist_set = CustomSet::new(
            env::var("NFTBLOCKD_CUSTOM_BLOCKLIST_SET_NAME")
                .unwrap_or("custom_blocklist_set".to_string()),
            parse_from_string(
                read_ip_set_file(
                    env::var("NFTBLOCKD_CUSTOM_BLOCKLIST_PATH_IPV4")
                        .ok()
                        .as_ref(),
                )?,
                delimiter,
            ),
            parse_from_string(
                read_ip_set_file(
                    env::var("NFTBLOCKD_CUSTOM_BLOCKLIST_PATH_IPV6")
                        .ok()
                        .as_ref(),
                )?,
                delimiter,
            ),
        )?;

        Ok(NftConfig {
            table_name: env::var("NFTBLOCKD_TABLE_NAME").unwrap_or("nftblockd".to_string()),
            prerouting_chain: env::var("NFTBLOCKD_PREROUTING_CHAIN_NAME")
                .unwrap_or("prerouting".to_string()),
            postrouting_chain: env::var("NFTBLOCKD_POSTROUTING_CHAIN_NAME")
                .unwrap_or("postrouting".to_string()),
            blocklist_set_name: env::var("NFTBLOCKD_BLOCKLIST_SET_NAME")
                .unwrap_or("blocklist_set".to_string()),
            anti_lockout_set,
            custom_blocklist_set,
        })
    }

    /// Deletes the specified `nftables` table and its contents by applying the delete operation.
    ///
    /// # Errors
    /// Returns an `AppError` if the table cannot be deleted.
    pub fn delete_table_and_apply(&self) -> Result<(), AppError> {
        let ruleset = NftRulesetBuilder::new()
            .delete_table(&self.table_name)
            .build_ruleset();
        helper::apply_ruleset(&ruleset)?;
        info!(
            "the `{}` table and all its contents have been deleted",
            self.table_name
        );
        Ok(())
    }

    /// Generates the complete `nftables` ruleset for the current configuration.
    /// This includes table, sets, chains, and rules for IPv4 and IPv6 blocklists and anti-lockout rules.
    ///
    /// # Parameters
    /// - `ipv4_elements`: Optional IPv4 blocklist elements to include in the ruleset.
    /// - `ipv6_elements`: Optional IPv6 blocklist elements to include in the ruleset.
    ///
    /// # Returns
    /// A fully constructed `Nftables` structure containing all objects.
    #[allow(clippy::too_many_lines)]
    #[must_use]
    pub fn generate_ruleset(
        &'a self,
        ipv4_elements: &'a Option<SetElements<'a>>,
        ipv6_elements: &'a Option<SetElements<'a>>,
    ) -> Nftables<'a> {
        let ipv4_blocklist_set_name = format!("{}_ipv4", self.blocklist_set_name);
        let ipv6_blocklist_set_name = format!("{}_ipv6", self.blocklist_set_name);
        let ipv4_anti_lockout_set_name = format!("{}_ipv4", self.anti_lockout_set.set_name);
        let ipv6_anti_lockout_set_name = format!("{}_ipv6", self.anti_lockout_set.set_name);
        let ipv4_custom_blocklist_set_name = format!("{}_ipv4", self.custom_blocklist_set.set_name);
        let ipv6_custom_blocklist_set_name = format!("{}_ipv6", self.custom_blocklist_set.set_name);

        let table = self.table_name.as_str();

        let mut batch = Batch::new();
        let table_new = Table::new(table.as_ref(), ProtoFamily::Inet);



        let mut builder = NftRulesetBuilder::new()
            .build_table(table)
            .delete_table(table)
            .build_table(table)
            .build_chain(
                table,
                self.prerouting_chain.as_str(),
                NfHook::Prerouting,
                -300,
            )
            .build_chain(
                table,
                self.postrouting_chain.as_str(),
                NfHook::Postrouting,
                300,
            )
            .build_set(
                table,
                ipv4_anti_lockout_set_name.clone(),
                &SetType::Ipv4Addr,
            )
            .build_set(
                table,
                ipv6_anti_lockout_set_name.clone(),
                &SetType::Ipv6Addr,
            )
            .build_set(table, ipv4_blocklist_set_name.clone(), &SetType::Ipv4Addr)
            .build_set(table, ipv6_blocklist_set_name.clone(), &SetType::Ipv6Addr)
            .build_set(
                table,
                ipv4_custom_blocklist_set_name.clone(),
                &SetType::Ipv4Addr,
            )
            .build_set(
                table,
                ipv6_custom_blocklist_set_name.clone(),
                &SetType::Ipv6Addr,
            )
            .build_rule(
                table,
                self.prerouting_chain.as_str(),
                ipv4_anti_lockout_set_name.clone(),
                RuleProto::Ip,
                RuleDirection::Saddr,
                false,
                Statement::Accept(None),
                "prerouting ipv4 anti-lockout rule",
            )
            .build_rule(
                table,
                self.prerouting_chain.as_str(),
                ipv6_anti_lockout_set_name.clone(),
                RuleProto::Ip6,
                RuleDirection::Saddr,
                false,
                Statement::Accept(None),
                "prerouting ipv6 anti-lockout rule",
            )
            .build_rule(
                table,
                self.postrouting_chain.as_str(),
                ipv4_anti_lockout_set_name.clone(),
                RuleProto::Ip,
                RuleDirection::Daddr,
                false,
                Statement::Accept(None),
                "postrouting ipv4 anti-lockout rule",
            )
            .build_rule(
                table,
                self.postrouting_chain.as_str(),
                ipv6_anti_lockout_set_name.clone(),
                RuleProto::Ip6,
                RuleDirection::Daddr,
                false,
                Statement::Accept(None),
                "postrouting ipv6 anti-lockout rule",
            )
            .build_rule(
                table,
                self.prerouting_chain.as_str(),
                ipv4_custom_blocklist_set_name.clone(),
                RuleProto::Ip,
                RuleDirection::Saddr,
                true,
                Statement::Drop(None),
                "prerouting ipv4 custom blocklist rule",
            )
            .build_rule(
                table,
                self.prerouting_chain.as_str(),
                ipv6_custom_blocklist_set_name.clone(),
                RuleProto::Ip6,
                RuleDirection::Saddr,
                true,
                Statement::Drop(None),
                "prerouting ipv6 custom blocklist rule",
            )
            .build_rule(
                table,
                self.postrouting_chain.as_str(),
                ipv4_custom_blocklist_set_name.clone(),
                RuleProto::Ip,
                RuleDirection::Daddr,
                true,
                Statement::Drop(None),
                "postrouting ipv4 custom blocklist rule",
            )
            .build_rule(
                table,
                self.postrouting_chain.as_str(),
                ipv6_custom_blocklist_set_name.clone(),
                RuleProto::Ip6,
                RuleDirection::Daddr,
                true,
                Statement::Drop(None),
                "postrouting ipv6 custom blocklist rule",
            )
            .build_rule(
                table,
                self.prerouting_chain.as_str(),
                ipv4_blocklist_set_name.clone(),
                RuleProto::Ip,
                RuleDirection::Saddr,
                true,
                Statement::Drop(None),
                "prerouting ipv4 blocklist rule",
            )
            .build_rule(
                table,
                self.prerouting_chain.as_str(),
                ipv6_blocklist_set_name.clone(),
                RuleProto::Ip6,
                RuleDirection::Saddr,
                true,
                Statement::Drop(None),
                "prerouting ipv6 blocklist rule",
            )
            .build_rule(
                table,
                self.postrouting_chain.as_str(),
                ipv4_blocklist_set_name.clone(),
                RuleProto::Ip,
                RuleDirection::Daddr,
                true,
                Statement::Drop(None),
                "postrouting ipv4 blocklist rule",
            )
            .build_rule(
                table,
                self.postrouting_chain.as_str(),
                ipv6_blocklist_set_name.clone(),
                RuleProto::Ip6,
                RuleDirection::Daddr,
                true,
                Statement::Drop(None),
                "postrouting ipv6 blocklist rule",
            );

        if let Some(ipv4_elements) = &self.anti_lockout_set.ipv4_elements {
            builder = builder.build_set_elements(table, ipv4_anti_lockout_set_name, ipv4_elements);
        }

        if let Some(ipv6_elements) = &self.anti_lockout_set.ipv6_elements {
            builder = builder.build_set_elements(table, ipv6_anti_lockout_set_name, ipv6_elements);
        }

        if let Some(ipv4_elements) = &self.custom_blocklist_set.ipv4_elements {
            builder =
                builder.build_set_elements(table, ipv4_custom_blocklist_set_name, ipv4_elements);
        }

        if let Some(ipv6_elements) = &self.custom_blocklist_set.ipv6_elements {
            builder =
                builder.build_set_elements(table, ipv6_custom_blocklist_set_name, ipv6_elements);
        }

        if let Some(ipv4_elements) = ipv4_elements {
            builder = builder.build_set_elements(table, ipv4_blocklist_set_name, ipv4_elements);
        }

        if let Some(ipv6_elements) = ipv6_elements {
            builder = builder.build_set_elements(table, ipv6_blocklist_set_name, ipv6_elements);
        }

        builder.build_ruleset()
    }

    /// Applies the generated `nftables` ruleset to the system.
    ///
    /// This function takes optional IPv4 and IPv6 blocklist elements, generates
    /// a corresponding `nftables` ruleset using the current configuration, and applies it.
    ///
    /// # Parameters
    /// - `ipv4_elements`: Optional set of IPv4 blocklist elements.
    /// - `ipv6_elements`: Optional set of IPv6 blocklist elements.
    ///
    /// # Returns
    /// - `Ok(())` if the ruleset was successfully applied.
    /// - `Err(AppError)` if there was an error in generating or applying the ruleset.
    ///
    /// # Errors
    /// - Returns an `AppError` if the process of applying the ruleset fails.
    /// - An error may occur if the `nftables` configuration is invalid or communication with
    ///   the `nftables` subsystem fails.
    pub fn apply_nft(
        &self,
        ipv4_elements: &Option<SetElements<'a>>,
        ipv6_elements: &Option<SetElements<'a>>,
    ) -> Result<(), AppError> {
        let ruleset = self.generate_ruleset(ipv4_elements, ipv6_elements);
        debug!(
            "ruleset: {}",
            serde_json::to_string_pretty(&ruleset)
                .unwrap_or("Could not convert ruleset to JSON".to_string())
        );
        helper::apply_ruleset(&ruleset)?;
        Ok(())
    }
}
