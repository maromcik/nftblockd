#[derive(Default, Debug, Clone)]
pub struct Stats {
    pub dropped_packets: u128,
    pub dropped_bytes: u128,
}
