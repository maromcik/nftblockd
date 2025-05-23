use crate::anti_lockout::AntiLockoutSet;
use crate::error::AppError;
use crate::network::BlockListNetwork;
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

pub enum RuleDirection {
    Saddr,
    Daddr,
}

pub enum RuleProto {
    Ip,
    Ip6,
}

impl Display for RuleDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleDirection::Saddr => write!(f, "saddr"),
            RuleDirection::Daddr => write!(f, "daddr"),
        }
    }
}

impl Display for RuleProto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleProto::Ip => write!(f, "ip"),
            RuleProto::Ip6 => write!(f, "ip6"),
        }
    }
}

pub struct NftConfig<'a> {
    pub table_name: String,
    pub prerouting_chain: String,
    pub postrouting_chain: String,
    pub blocklist_set_name: String,
    pub anti_lockout_set_name: String,
    pub anti_lockout_ipv4: Option<SetElements<'a>>,
    pub anti_lockout_ipv6: Option<SetElements<'a>>,
}

impl<'a> NftConfig<'a> {
    pub fn new() -> Result<Self, AppError> {
        let anti_lockout_ipv4_string = env::var("NFTABLES_BLOCKLIST_ANTI_LOCKOUT_IPV4").ok();
        let anti_lockout_ipv4 = anti_lockout_ipv4_string
            .map(|s| AntiLockoutSet::IPv4(s).build_anti_lockout())
            .transpose()?;

        let anti_lockout_ipv6_string = env::var("NFTABLES_BLOCKLIST_ANTI_LOCKOUT_IPV6").ok();
        let anti_lockout_ipv6 = anti_lockout_ipv6_string
            .map(|s| AntiLockoutSet::IPv6(s).build_anti_lockout())
            .transpose()?;

        Ok(NftConfig {
            table_name: env::var("NFTABLES_BLOCKLIST_TABLE_NAME").unwrap_or("blocklist".into()),
            prerouting_chain: env::var("NFTABLES_BLOCKLIST_PREROUTING_CHAIN_NAME")
                .unwrap_or("prerouting".into()),
            postrouting_chain: env::var("NFTABLES_BLOCKLIST_POSTROUTING_CHAIN_NAME")
                .unwrap_or("postrouting".into()),
            blocklist_set_name: env::var("NFTABLES_BLOCKLIST_BLOCKLIST_SET_NAME")
                .unwrap_or("blocklist_set".into()),
            anti_lockout_set_name: env::var("NFTABLES_BLOCKLIST_ANTI_LOCKOUT_SET_NAME")
                .unwrap_or("anti_lockout_set".into()),
            anti_lockout_ipv4,
            anti_lockout_ipv6,
        })
    }

    fn delete_table(table_name: &'a str) -> NfObject<'a> {
        NfObject::CmdObject(Delete(Table(schema::Table {
            family: NfFamily::INet,
            name: table_name.into(),
            handle: None,
        })))
    }

    fn build_table(table_name: &'a str) -> NfObject<'a> {
        NfObject::ListObject(Table(schema::Table {
            family: NfFamily::INet,
            name: table_name.into(),
            ..Default::default()
        }))
    }

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
            hook: Some(chain_hook),
            prio: Some(priority),
            dev: None,
            policy: Some(NfChainPolicy::Accept),
        }))
    }

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

        expressions.extend(vec![Statement::Counter(Counter::Anonymous(None)), verdict]);

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

pub fn get_nft_expressions<'a, T>(ips: Vec<T>) -> SetElements<'a>
where
    T: BlockListNetwork,
{
    ips.iter()
        .map(|ip| {
            Expression::Named(NamedExpression::Prefix(Prefix {
                addr: Box::new(Expression::String(Cow::from(ip.network_string()))),
                len: ip.network_prefix() as u32,
            }))
        })
        .collect::<Vec<Expression>>()
}
