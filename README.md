# nftables blocklist updater

Fetches IPs that are added to a blocklist

## Installation

```shell
# install rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# build
cargo build --release

# copy to /usr/local/sbin
cp target/release/nftables-blocklist-updater /usr/local/sbin/
```

## Usage
Use with the provided blocklist table in `nftables/blocklist/blocklist.nft
