use crate::error::AppError;
use nftables::expr::Expression;
use nftables::schema::NfListObject::{Chain, Element, Set, Table};
use nftables::schema::{NfObject, Nftables, SetType};
use nftables::types::{NfChainPolicy, NfFamily, NfHook};
use nftables::{helper, schema, types};
use std::borrow::Cow;
use std::collections::HashSet;
use nftables::schema::NfCmd::Delete;

pub type SetElements<'a> = Vec<Expression<'a>>;

pub struct NftConfig<'a> {
    pub table_name: &'a str,
    pub prerouting_chain: &'a str,
    pub postrouting_chain: &'a str,
    pub blocklist_set_name: &'a str,
    pub anti_lockout_set_name: &'a str,
}

impl<'a> NftConfig<'a> {
    pub fn new(
        table_name: &'a str,
        prerouting_chain: &'a str,
        postrouting_chain: &'a str,
        blocklist_set_name: &'a str,
        anti_lockout_set_name: &'a str,
    ) -> NftConfig<'a> {
        NftConfig {
            table_name,
            prerouting_chain,
            postrouting_chain,
            blocklist_set_name,
            anti_lockout_set_name,
        }
    }

    pub fn delete_table(table_name: &'a str) -> NfObject<'a> {
        NfObject::CmdObject(Delete(Table(schema::Table {
            family: NfFamily::INet,
            name: table_name.into(),
            handle: None,
        })))
    }

    pub fn build_table(table_name: &'a str) -> NfObject<'a> {
        NfObject::ListObject(Table(schema::Table {
            family: NfFamily::INet,
            name: table_name.into(),
            ..Default::default()
        }))
    }

    pub fn build_chain(table_name: &'a str, chain_name: &'a str, chain_hook: NfHook, priority: i32) -> NfObject<'a> {
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

    pub fn build_set(
        table_name: &'a str,
        set_name: String,
        set_type: &SetType,
    ) -> NfObject<'a> {
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

    pub fn build_set_elements(
        table_name: &'a str,
        set_name: String,
        set_elements: Vec<Expression<'a>>,
    ) -> NfObject<'a> {
        NfObject::ListObject(Element(schema::Element {
            family: NfFamily::INet,
            table: table_name.into(),
            name: set_name.into(),
            elem: Cow::Owned(set_elements),
        }))
    }
    
    
    pub fn generate_ruleset(
        &self,
        ipv4_elements: Option<SetElements<'a>>,
        ipv6_elements: Option<SetElements<'a>>,
    ) -> Nftables<'a> {
        let ipv4_set_name = format!("{}_ipv4", self.blocklist_set_name);
        let ipv6_set_name = format!("{}_ipv6", self.blocklist_set_name);
        let mut objects = vec![
            NftConfig::delete_table(self.table_name),
            NftConfig::build_table(self.table_name),
            NftConfig::build_chain(self.table_name, self.prerouting_chain, NfHook::Prerouting, -300),
            NftConfig::build_chain(self.table_name, self.postrouting_chain, NfHook::Postrouting, 300),
            NftConfig::build_set(self.table_name, ipv4_set_name.clone(), &SetType::Ipv4Addr),
            NftConfig::build_set(self.table_name, ipv6_set_name.clone(), &SetType::Ipv6Addr),
        ];
        
        if let Some(ipv4_elements) = ipv4_elements {
            objects.push(Self::build_set_elements(self.table_name, ipv4_set_name, ipv4_elements));
        }

        if let Some(ipv6_elements) = ipv6_elements {
            objects.push(Self::build_set_elements(self.table_name, ipv6_set_name, ipv6_elements));
        }
        
        Nftables {
            objects: Cow::from(objects),
        }
    }

    pub fn apply_nft(&self, ipv4_elements: Option<SetElements<'a>>, ipv6_elements: Option<SetElements<'a>>) -> Result<(), AppError> {
        let ruleset = self.generate_ruleset(ipv4_elements, ipv6_elements);
        // println!("{}", serde_json::to_string_pretty(&ruleset).unwrap());
        helper::apply_ruleset(&ruleset)?;
        Ok(())
    }
}
