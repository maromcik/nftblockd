use crate::error::AppError;
use crate::nftables::SetElements;
use crate::subnet::{SubnetList, parse_from_string};

pub enum AntiLockoutSet {
    IPv4(String),
    IPv6(String),
}
impl AntiLockoutSet {
    pub fn build_anti_lockout<'a>(self) -> Result<SetElements<'a>, AppError> {
        match self {
            AntiLockoutSet::IPv4(s) => {
                let ips = parse_from_string(s.as_str());
                Ok(SubnetList::IPv4(ips)
                    .validate_blocklist()?
                    .deduplicate()?
                    .to_nft_expression()
                    .get_elements())
            }
            AntiLockoutSet::IPv6(s) => {
                let ips = parse_from_string(s.as_str());
                Ok(SubnetList::IPv6(ips)
                    .validate_blocklist()?
                    .deduplicate()?
                    .to_nft_expression()
                    .get_elements())
            }
        }
    }
}
