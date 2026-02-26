use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString};
use std::fmt::Display;
use nftnl::{Batch, Chain, Policy, ProtoFamily, Table};
use crate::error::AppError;
// pub type SetElements<'a> = Vec<Expression<'a>>;

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

#[derive(Default)]
pub struct NftRulesetBuilder<'a> {
    pub batch: nftnl::Batch,
    pub tables: HashMap<&'a str, nftnl::Table>,
    pub chains: HashMap<&'a str, nftnl::Chain<'a>>,
}

impl<'a> NftRulesetBuilder<'a> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            batch: Batch::new(),
            tables: HashMap::new(),
            chains: HashMap::new(),
        }
    }

    /// Deletes an existing table in `nftables`. This operation removes the table
    /// and all related chains, sets, and rules.
    ///
    /// # Parameters
    /// - `table_name`: The name of the table to delete.
    ///
    /// # Returns
    /// An `NfObject` encapsulating the delete operation.
    #[must_use]
    pub fn delete_table(mut self, table_name: &str) -> Result<Self, AppError> {
        let c_table_name = CString::new(table_name)?;
        let table = Table::new(c_table_name.as_ref(), ProtoFamily::Inet);
        self.batch.add(&table, nftnl::MsgType::Del);
        Ok(self)
    }

    /// Creates (or declares) a new table in `nftables`.
    ///
    /// # Parameters
    /// - `table_name`: The name of the table to create.
    ///
    /// # Returns
    /// An `NfObject` encapsulating the create operation.
    #[must_use]
    pub fn build_table(mut self, table_name: &'a str) -> Result<Self, AppError> {
        let c_table_name = CString::new(table_name)?;
        let table = Table::new(c_table_name.as_ref(), ProtoFamily::Inet);
        self.batch.add(&table, nftnl::MsgType::Add);
        self.tables.entry(table_name).or_insert(table);
        Ok(self)
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
    #[must_use]
    pub fn build_chain(
        mut self,
        table_name: &'a str,
        chain_name: &'a str,
        chain_hook: nftnl::Hook,
        priority: i32,
    ) -> Result<Self, AppError> {
        let c_chain_name = CString::new(chain_name)?;
        let table = self.tables.get(table_name).ok_or(AppError::TableNotFound(table_name.to_string()))?;
        let mut chain = Chain::new(c_chain_name.as_ref(), &table);
        chain.set_hook(chain_hook, priority);
        chain.set_policy(Policy::Accept);
        chain.set_type(nftnl::ChainType::Filter);
        self.batch.add(&chain, nftnl::MsgType::Add);
        Ok(self)
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
    #[must_use]
    pub fn build_set(mut self, table_name: &'a str, set_name: String, set_type: &SetType) -> Result<Self, AppError> {
        let c_set_name = CString::new(set_name.clone())?;
        let table = self.tables.remove(table_name).ok_or(AppError::TableNotFound(table_name.to_string()))?;
        let set = nftnl::set::Set::new(c_set_name.as_ref(), 0, &table, ProtoFamily::Inet);
        nftnl::set::Set::add(nftnl::nft_set!())
        self.batch
            .push(NfObject::ListObject(Set(Box::new(schema::Set {
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
            }))));
        self
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
    #[must_use]
    pub fn build_set_elements(
        mut self,
        table_name: &'a str,
        set_name: String,
        set_elements: &'a Vec<Expression<'a>>,
    ) -> Self {
        self.batch
            .push(NfObject::ListObject(Element(schema::Element {
                family: NfFamily::INet,
                table: table_name.into(),
                name: set_name.into(),
                elem: Cow::Borrowed(set_elements),
            })));
        self
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
    #[must_use]
    pub fn build_rule(
        mut self,
        table_name: &'a str,
        chain_name: &'a str,
        set_name: String,
        rule_proto: RuleProto,
        rule_direction: RuleDirection,
        log: bool,
        verdict: Statement<'a>,
        comment: &'a str,
    ) -> Self {
        // Match condition against the specified `set_name`.
        let mut expressions = vec![Statement::Match(Match {
            left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                PayloadField {
                    protocol: rule_proto.to_string().into(),
                    field: rule_direction.to_string().into(),
                },
            ))),
            right: Expression::String(Cow::Owned(format!("@{set_name}"))),
            op: Operator::EQ,
        })];

        // Optionally, add a log statement to the rule.
        if log {
            expressions.push(Statement::Log(Some(Log {
                prefix: log.then(|| {
                    Cow::Owned(format!("{table_name};{chain_name};{set_name};dropped: ",))
                }),
                group: None,
                snaplen: None,
                queue_threshold: None,
                level: None,
                flags: None,
            })));
        }

        // Add counter and verdict to the rule.
        // expressions.extend(vec![Statement::Counter(Counter::Anonymous(None)), verdict]);
        expressions.extend(vec![verdict]);
        // Return the completed `NfObject` for the rule.
        let rule = NfObject::ListObject(Rule(schema::Rule {
            family: NfFamily::INet,
            table: table_name.into(),
            chain: chain_name.into(),
            expr: Cow::Owned(expressions),
            handle: None,
            index: None,
            comment: Some(Cow::from(comment)),
        }));
        self.batch.push(rule);
        self
    }

    #[must_use]
    pub fn build_ruleset(self) -> Nftables<'a> {
        Nftables {
            objects: Cow::from(self.batch),
        }
    }
}
