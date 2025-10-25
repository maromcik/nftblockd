use crate::error::AppError;
use crate::nftables::SetElements;
use crate::subnet::SubnetList;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomSet<'a> {
    pub set_name: String,
    pub ipv4_elements: Option<SetElements<'a>>,
    pub ipv6_elements: Option<SetElements<'a>>,
}

impl<'a> CustomSet<'a> {
    pub fn new(
        set_name: String,
        ipv4_data: Option<Vec<String>>,
        ipv6_data: Option<Vec<String>>,
    ) -> Result<Self, AppError> {
        let ipv4_elements = ipv4_data.map_or_else(
            || Ok::<Option<SetElements>, AppError>(None),
            |ips| {
                Ok(SubnetList::IPv4(ips)
                    .validate_blocklist(true)?
                    .deduplicate()?
                    .transform_to_nft_expressions()
                    .get_elements())
            },
        )?;

        let ipv6_elements = ipv6_data.map_or_else(
            || Ok::<Option<SetElements>, AppError>(None),
            |ips| {
                Ok(SubnetList::IPv6(ips)
                    .validate_blocklist(true)?
                    .deduplicate()?
                    .transform_to_nft_expressions()
                    .get_elements())
            },
        )?;

        Ok(Self {
            set_name,
            ipv4_elements,
            ipv6_elements,
        })
    }
}
