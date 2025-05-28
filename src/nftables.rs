use crate::anti_lockout::AntiLockoutSet;
use crate::error::AppError;
use crate::network::ListNetwork;
use log::{debug, info};
use nftables::expr::{Expression, NamedExpression, Payload, PayloadField, Prefix};
use nftables::schema::NfCmd::Delete;
use nftables::schema::NfListObject::{Chain, Element, Rule, Set, Table};
use nftables::schema::{NfObject, Nftables, SetType};
use nftables::stmt::{Counter, Log, Match, Operator, Statement};
use nftables::types::{NfChainPolicy, NfFamily, NfHook};
use nftables::{helper, schema, types};
use std::borrow::Cow;
use std::collections::HashSet;
use std::env;
use std::fmt::Display;

pub type SetElements<'a> = Vec<Expression<'a>>;

/// Converts a vector of subnets into `nftables` expressions.
///
/// # Type Parameters
/// - `T`: A type implementing the `BlockListNetwork` trait (e.g., `Ipv4Network`, `Ipv6Network`).
///
/// # Parameters
/// - `ips`: A vector of subnets `T` to be transformed.
///
/// # Returns
/// A `SetElements` vector of `nftables` expressions.
pub fn get_nft_expressions<'a, T>(ips: Option<Vec<T>>) -> Option<SetElements<'a>>
where
    T: ListNetwork,
{
    Some(
        ips?.iter()
            .map(|ip| {
                Expression::Named(NamedExpression::Prefix(Prefix {
                    addr: Box::new(Expression::String(Cow::from(ip.network_string()))),
                    len: ip.network_prefix() as u32,
                }))
            })
            .collect::<Vec<Expression>>(),
    )
}

/// Represents the direction of a rule in the firewall chain (source or destination).
pub enum RuleDirection {
    /// Source address (saddr).
    Saddr,
    /// Destination address (daddr).
    Daddr,
}

/// Represents the protocol type (IPv4 or IPv6) for a rule.
pub enum RuleProto {
    /// IPv4 protocol.
    Ip,
    /// IPv6 protocol.
    Ip6,
}

impl Display for RuleDirection {
    /// Converts `RuleDirection` into its string representation for use in rule expressions:
    /// - `Saddr` -> "saddr"
    /// - `Daddr` -> "daddr".
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleDirection::Saddr => write!(f, "saddr"),
            RuleDirection::Daddr => write!(f, "daddr"),
        }
    }
}

impl Display for RuleProto {
    /// Converts `RuleProto` into its string representation for use in rule expressions:
    /// - `Ip` -> "ip"
    /// - `Ip6` -> "ip6".
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleProto::Ip => write!(f, "ip"),
            RuleProto::Ip6 => write!(f, "ip6"),
        }
    }
}

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
    /// Name of the anti-lockout set to prevent self-blocking.
    pub anti_lockout_set_name: String,
    /// Anti-lockout rules for IPv4 (optional).
    pub anti_lockout_ipv4: Option<SetElements<'a>>,
    /// Anti-lockout rules for IPv6 (optional).
    pub anti_lockout_ipv6: Option<SetElements<'a>>,
}

impl<'a> NftConfig<'a> {
    /// Creates a new `NftConfig` by fetching configuration values from environment variables.
    ///
    /// # Returns
    /// A populated `NftConfig` instance with default values for unspecified environment variables.
    ///
    /// # Errors
    /// Returns an `AppError` if anti-lockout rules fail to load/parse.
    pub fn new() -> Result<Self, AppError> {
        // Load IPv4 anti-lockout rules from environment variable.
        let anti_lockout_ipv4 = AntiLockoutSet::IPv4(env::var("NFTBLOCKD_ANTI_LOCKOUT_IPV4").ok())
            .build_anti_lockout()?;

        // Load IPv6 anti-lockout rules from environment variable.
        let anti_lockout_ipv6 = AntiLockoutSet::IPv6(env::var("NFTBLOCKD_ANTI_LOCKOUT_IPV6").ok())
            .build_anti_lockout()?;

        Ok(NftConfig {
            table_name: env::var("NFTBLOCKD_TABLE_NAME").unwrap_or("nftblockd".to_string()),
            prerouting_chain: env::var("NFTBLOCKD_PREROUTING_CHAIN_NAME")
                .unwrap_or("prerouting".to_string()),
            postrouting_chain: env::var("NFTBLOCKD_POSTROUTING_CHAIN_NAME")
                .unwrap_or("postrouting".to_string()),
            blocklist_set_name: env::var("NFTBLOCKD_BLOCKLIST_SET_NAME")
                .unwrap_or("blocklist_set".to_string()),
            anti_lockout_set_name: env::var("NFTBLOCKD_ANTI_LOCKOUT_SET_NAME")
                .unwrap_or("anti_lockout_set".to_string()),
            anti_lockout_ipv4,
            anti_lockout_ipv6,
        })
    }

    /// Deletes an existing table in `nftables`. This operation removes the table
    /// and all related chains, sets, and rules.
    ///
    /// # Parameters
    /// - `table_name`: The name of the table to delete.
    ///
    /// # Returns
    /// An `NfObject` encapsulating the delete operation.
    fn delete_table(table_name: &'a str) -> NfObject<'a> {
        NfObject::CmdObject(Delete(Table(schema::Table {
            family: NfFamily::INet,
            name: table_name.into(),
            handle: None,
        })))
    }

    /// Creates (or declares) a new table in `nftables`.
    ///
    /// # Parameters
    /// - `table_name`: The name of the table to create.
    ///
    /// # Returns
    /// An `NfObject` encapsulating the create operation.
    fn build_table(table_name: &'a str) -> NfObject<'a> {
        NfObject::ListObject(Table(schema::Table {
            family: NfFamily::INet, // Use the `inet` family, which supports both IPv4 and IPv6.
            name: table_name.into(),
            ..Default::default()
        }))
    }

    /// Builds a chain within a specific table, associating it with a particular hook (e.g., `prerouting`).
    ///
    /// # Parameters
    /// - `table_name`: The name of the table containing the chain.
    /// - `chain_name`: The name of the chain to create.
    /// - `chain_hook`: The hook to associate with (e.g., `prerouting`, `postrouting`).
    /// - `priority`: The priority for the chain hook (-300 for `prerouting`, +300 for `postrouting`).
    ///
    /// # Returns
    /// An `NfObject` encapsulating the chain creation operation.
    fn build_chain(
        table_name: &'a str,
        chain_name: &'a str,
        chain_hook: NfHook,
        priority: i32,
    ) -> NfObject<'a> {
        NfObject::ListObject(Chain(schema::Chain {
            family: NfFamily::INet,
            table: table_name.into(),
            name: chain_name.into(),
            newname: None,
            handle: None,
            _type: Some(types::NfChainType::Filter),
            hook: Some(chain_hook), // Assign to a specific hook (prerouting/postrouting).
            prio: Some(priority),   // Hook priority determines order.
            dev: None,
            policy: Some(NfChainPolicy::Accept), // Default policy is "accept".
        }))
    }

    /// Creates a set structure in the `nftables` ruleset.
    ///
    /// # Parameters
    /// - `table_name`: The name of the table the set belongs to.
    /// - `set_name`: The name of the set to create.
    /// - `set_type`: The data type of elements in the set (e.g., `Ipv4Addr`, `Ipv6Addr`).
    ///
    /// # Returns
    /// An `NfObject` representing the creation of the set.
    fn build_set(table_name: &'a str, set_name: String, set_type: &SetType) -> NfObject<'a> {
        NfObject::ListObject(Set(Box::new(schema::Set {
            family: NfFamily::INet,
            table: table_name.into(),
            name: set_name.into(),
            handle: None,
            set_type: schema::SetTypeValue::Single(*set_type),
            policy: None,
            flags: Some(HashSet::from([schema::SetFlag::Interval])),
            elem: None,
            timeout: None,
            gc_interval: None,
            size: None,
            comment: None,
        })))
    }

    /// Inserts elements into an existing set within `nftables`.
    ///
    /// # Parameters
    /// - `table_name`: The name of the table.
    /// - `set_name`: The name of the set being updated.
    /// - `set_elements`: The elements to insert into the set (as expressions).
    ///
    /// # Returns
    /// An `NfObject` containing the set update operation.
    fn build_set_elements(
        table_name: &'a str,
        set_name: String,
        set_elements: &'a Vec<Expression<'a>>,
    ) -> NfObject<'a> {
        NfObject::ListObject(Element(schema::Element {
            family: NfFamily::INet,
            table: table_name.into(),
            name: set_name.into(),
            elem: Cow::Borrowed(set_elements),
        }))
    }

    /// Builds a firewall rule for a `nftables` chain.
    ///
    /// # Parameters
    /// - `table_name`: The table containing the rule.
    /// - `chain_name`: The chain to which the rule will be added.
    /// - `set_name`: The name of the `nftables` set referenced in the rule.
    /// - `rule_proto`: The protocol type (e.g., IPv4 or IPv6).
    /// - `rule_direction`: The address direction (e.g., source or destination).
    /// - `log`: Whether the rule should trigger logging.
    /// - `verdict`: The final action of the rule (e.g., drop, accept).
    /// - `comment`: A descriptive comment about the purpose of the rule.
    ///
    /// # Returns
    /// An `NfObject` representing the rule.
    #[allow(clippy::too_many_arguments)]
    fn build_rule(
        table_name: &'a str,
        chain_name: &'a str,
        set_name: String,
        rule_proto: RuleProto,
        rule_direction: RuleDirection,
        log: bool,
        verdict: Statement<'a>,
        comment: &'a str,
    ) -> NfObject<'a> {
        // Match condition against the specified `set_name`.
        let mut expressions = vec![Statement::Match(Match {
            left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                PayloadField {
                    protocol: rule_proto.to_string().into(),
                    field: rule_direction.to_string().into(),
                },
            ))),
            right: Expression::String(Cow::Owned(format!("@{}", set_name))),
            op: Operator::EQ,
        })];

        // Optionally add a log statement to the rule.
        if log {
            expressions.push(Statement::Log(Some(Log {
                prefix: log.then(|| Cow::Owned(format!("blocklist;{};dropped: ", chain_name))),
                group: None,
                snaplen: None,
                queue_threshold: None,
                level: None,
                flags: None,
            })))
        }

        // Add counter and verdict to the rule.
        expressions.extend(vec![Statement::Counter(Counter::Anonymous(None)), verdict]);

        // Return the completed `NfObject` for the rule.
        NfObject::ListObject(Rule(schema::Rule {
            family: NfFamily::INet,
            table: table_name.into(),
            chain: chain_name.into(),
            expr: Cow::Owned(expressions),
            handle: None,
            index: None,
            comment: Some(Cow::from(comment)),
        }))
    }

    // fn build_rules(
    //
    // )

    /// Deletes the specified `nftables` table and its contents by applying the delete operation.
    ///
    /// # Errors
    /// Returns an `AppError` if the table cannot be deleted.
    pub fn delete_table_and_apply(&self) -> Result<(), AppError> {
        let ruleset = Nftables {
            objects: Cow::from(vec![NftConfig::delete_table(self.table_name.as_str())]),
        };
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
    pub fn generate_ruleset(
        &'a self,
        ipv4_elements: &'a Option<SetElements<'a>>,
        ipv6_elements: &'a Option<SetElements<'a>>,
    ) -> Nftables<'a> {
        let ipv4_blocklist_set_name = format!("{}_ipv4", self.blocklist_set_name);
        let ipv6_blocklist_set_name = format!("{}_ipv6", self.blocklist_set_name);
        let ipv4_anti_lockout_set_name = format!("{}_ipv4", self.anti_lockout_set_name);
        let ipv6_anti_lockout_set_name = format!("{}_ipv6", self.anti_lockout_set_name);
        let mut objects = vec![
            NftConfig::build_table(self.table_name.as_str()),
            NftConfig::delete_table(self.table_name.as_str()),
            NftConfig::build_table(self.table_name.as_str()),
            NftConfig::build_chain(
                self.table_name.as_str(),
                self.prerouting_chain.as_str(),
                NfHook::Prerouting,
                -300,
            ),
            NftConfig::build_chain(
                self.table_name.as_str(),
                self.postrouting_chain.as_str(),
                NfHook::Postrouting,
                300,
            ),
            NftConfig::build_set(
                self.table_name.as_str(),
                ipv4_anti_lockout_set_name.clone(),
                &SetType::Ipv4Addr,
            ),
            NftConfig::build_set(
                self.table_name.as_str(),
                ipv6_anti_lockout_set_name.clone(),
                &SetType::Ipv6Addr,
            ),
            NftConfig::build_set(
                self.table_name.as_str(),
                ipv4_blocklist_set_name.clone(),
                &SetType::Ipv4Addr,
            ),
            NftConfig::build_set(
                self.table_name.as_str(),
                ipv6_blocklist_set_name.clone(),
                &SetType::Ipv6Addr,
            ),
            NftConfig::build_rule(
                self.table_name.as_str(),
                self.prerouting_chain.as_str(),
                ipv4_anti_lockout_set_name.clone(),
                RuleProto::Ip,
                RuleDirection::Saddr,
                false,
                Statement::Accept(None),
                "prerouting ipv4 anti-lockout rule",
            ),
            NftConfig::build_rule(
                self.table_name.as_str(),
                self.prerouting_chain.as_str(),
                ipv6_anti_lockout_set_name.clone(),
                RuleProto::Ip6,
                RuleDirection::Saddr,
                false,
                Statement::Accept(None),
                "prerouting ipv6 anti-lockout rule",
            ),
            NftConfig::build_rule(
                self.table_name.as_str(),
                self.postrouting_chain.as_str(),
                ipv4_anti_lockout_set_name.clone(),
                RuleProto::Ip,
                RuleDirection::Daddr,
                false,
                Statement::Accept(None),
                "postrouting ipv4 anti-lockout rule",
            ),
            NftConfig::build_rule(
                self.table_name.as_str(),
                self.postrouting_chain.as_str(),
                ipv6_anti_lockout_set_name.clone(),
                RuleProto::Ip6,
                RuleDirection::Daddr,
                false,
                Statement::Accept(None),
                "postrouting ipv6 anti-lockout rule",
            ),
            NftConfig::build_rule(
                self.table_name.as_str(),
                self.prerouting_chain.as_str(),
                ipv4_blocklist_set_name.clone(),
                RuleProto::Ip,
                RuleDirection::Saddr,
                true,
                Statement::Drop(None),
                "prerouting ipv4 blocklist rule",
            ),
            NftConfig::build_rule(
                self.table_name.as_str(),
                self.prerouting_chain.as_str(),
                ipv6_blocklist_set_name.clone(),
                RuleProto::Ip6,
                RuleDirection::Saddr,
                true,
                Statement::Drop(None),
                "prerouting ipv6 blocklist rule",
            ),
            NftConfig::build_rule(
                self.table_name.as_str(),
                self.postrouting_chain.as_str(),
                ipv4_blocklist_set_name.clone(),
                RuleProto::Ip,
                RuleDirection::Daddr,
                true,
                Statement::Drop(None),
                "postrouting ipv4 blocklist rule",
            ),
            NftConfig::build_rule(
                self.table_name.as_str(),
                self.postrouting_chain.as_str(),
                ipv6_blocklist_set_name.clone(),
                RuleProto::Ip6,
                RuleDirection::Daddr,
                true,
                Statement::Drop(None),
                "postrouting ipv6 blocklist rule",
            ),
        ];

        if let Some(ipv4_elements) = &self.anti_lockout_ipv4 {
            objects.push(Self::build_set_elements(
                self.table_name.as_str(),
                ipv4_anti_lockout_set_name,
                ipv4_elements,
            ));
        }

        if let Some(ipv6_elements) = &self.anti_lockout_ipv6 {
            objects.push(Self::build_set_elements(
                self.table_name.as_str(),
                ipv6_anti_lockout_set_name,
                ipv6_elements,
            ));
        }

        if let Some(ipv4_elements) = ipv4_elements {
            objects.push(Self::build_set_elements(
                self.table_name.as_str(),
                ipv4_blocklist_set_name,
                ipv4_elements,
            ));
        }

        if let Some(ipv6_elements) = ipv6_elements {
            objects.push(Self::build_set_elements(
                self.table_name.as_str(),
                ipv6_blocklist_set_name,
                ipv6_elements,
            ));
        }

        Nftables {
            objects: Cow::from(objects),
        }
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
        ipv4_elements: Option<SetElements<'a>>,
        ipv6_elements: Option<SetElements<'a>>,
    ) -> Result<(), AppError> {
        let ruleset = self.generate_ruleset(&ipv4_elements, &ipv6_elements);
        debug!(
            "ruleset: {}",
            serde_json::to_string_pretty(&ruleset).unwrap()
        );
        helper::apply_ruleset(&ruleset)?;
        Ok(())
    }
}
