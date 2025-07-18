# nftblockd

`nftblockd` is a robust Rust-based tool designed for managing IP blocklists in `nftables`. It provides an efficient and
secure mechanism to fetch, validate, deduplicate, and apply IPv4 and IPv6 subnets to a blocklist table in `nftables`.
The tool is geared toward optimizing network security with ease and reliability.

---

## Key Features

- **IPv4 and IPv6 Support**: Handles both IPv4 and IPv6 blocklists.
- **Automatic Blocklist Fetching**: Fetches blocklists from user-specified or environment-configured endpoints.
- **Validation and Deduplication**: Ensures subnets are valid, deduplicated, and free of redundancies using a trie-based
  algorithm.
- **High Performance**: Uses optimized data structures and algorithms for subnet deduplication.
- **Integration with `nftables`**: Directly applies blocklist rules to `nftables`.
- **Anti-Lockout Mechanism**: Protects the specified critical IPs from being locked out of the firewall by mistake.
- **Periodic Update Support**: Periodically fetches and updates the blocklists according to a user-configured interval.
- **Smart Logging**: Configurable logging levels via environment variables.

---

## Building

1. **Install Dependencies**  
   Ensure you have Rust installed on your system. If not, you can install it via [rustup](https://rustup.rs/):

```shell script
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

2. **Clone the Repository**:

```shell script
git clone https://github.com/maromcik/nftblockd.git
cd nftblockd
```

3. **Build the Binary**, use Cargo to build the project:

Standard build using `glibc`

```shell script
cargo build --release
```

More portable build using `musl`

```shell
rustup target add x86_64-unknown-linux-musl
cargo build --release --target=x86_64-unknown-linux-musl
```

4. **Run the Binary**:

Run the compiled binary (`glibc`):

```shell script
./target/release/nftblockd
```

Run the compiled binary (`musl`):

```shell script
./target/x86_64-unknown-linux-musl/release/nftblockd
```

---

## Installation

Either use the **nftables** Ansible role from [ansible-collections](https://gitlab.ics.muni.cz/ics/infra/shared/ansible-collections/-/tree/main/ais/linux/roles/nftables?ref_type=heads) or deploy it on your own.

### Deployment

Download the binary and run it:

```shell
wget https://gitlab.ics.muni.cz/api/v4/projects/7885/packages/generic/nftblockd/latest/nftblockd
nftblockd -e .env
```

Instead of the keyword latest, you can specify the desired [tag](https://gitlab.ics.muni.cz/ics/infra/shared/projects/nftblockd/-/tags)

## Usage

The general usage structure for `nftblockd` is:

```shell script
nftblockd [OPTIONS]
```

### Command-Line Options:

| Flag or Argument            | Description                                                                           | Default or Mandatory |
|-----------------------------|---------------------------------------------------------------------------------------|----------------------|
| `-4, --url4 <IPv4_URL>`     | The endpoint URL to fetch the IPv4 blocklist.                                         | Optional             |
| `-6, --url6 <IPv6_URL>`     | The endpoint URL to fetch the IPv6 blocklist.                                         | Optional             |
| `-i, --interval <INTERVAL>` | Time interval (in seconds) for periodic blocklist updates.                            | `30` (Default)       |
| `-e, --env-file <ENV_FILE>` | Specifies an `.env` file containing environment variable configurations for the tool. | Optional             |
| `-d, --delete`              | Deletes the existing blocklist table and stops the execution.                         | Flag, Optional       |

### Example Commands:

1. Fetch and apply an IPv4 blocklist from an HTTP endpoint:

```shell script
nftblockd --url4 https://example.com/ipv4-blocklist
```

2. Apply both IPv4 and IPv6 blocklists periodically with a 60-second interval:

```shell script
nftblockd --url4 https://example.com/ipv4-blocklist --url6 https://example.com/ipv6-blocklist --interval 60
```

3. Use environment variables from a custom `.env` file:

```shell script
nftblockd --env-file path/to/env/file
```

4. Delete the blocklist table manually:

```shell script
nftblockd --delete
```

---

## Configuration

`nftblockd` supports configuring various parameters through environment variables. Here's a list of the configurable
variables:

| Environment Variable               | Description                                                                                 | Default Value      |
|------------------------------------|---------------------------------------------------------------------------------------------|--------------------|
| `NFTBLOCKD_IPV4_URL`               | The IPv4 blocklist fetching URL.                                                            | None               |
| `NFTBLOCKD_IPV6_URL`               | The IPv6 blocklist fetching URL.                                                            | None               |
| `NFTBLOCKD_BLOCKLIST_SPLIT_STRING` | The string that is used to split the fetched blocklist                                      | Any whitespaces    |
| `NFTBLOCKD_REQUEST_HEADERS`        | A json in the format `{ "header_key1" : "header_value1", "header_key2" : "header_value2" }` | None               |
| `NFTBLOCKD_INTERVAL`               | Interval (in seconds) for updating blocklists.                                              | `30`               |
| `NFTBLOCKD_LOG_LEVEL`              | Logging level. Options: `debug`, `info`, `warn`, `error`.                                   | `info`             |
| `NFTBLOCKD_ANTI_LOCKOUT_IPV4`      | A whitespace separated list of IPv4 anti-lockout IPs (e.g., admin IP).                      | None               |
| `NFTBLOCKD_ANTI_LOCKOUT_IPV6`      | A whitespace separated list of IPv6 anti-lockout IPs (e.g., admin IP).                      | None               |
| `NFTBLOCKD_TABLE_NAME`             | The name of the `nftables` blocklist table.                                                 | `nftblockd`        |
| `NFTBLOCKD_PREROUTING_CHAIN_NAME`  | The name of the `nftables` prerouting chain in the blocklist table.                         | `prerouting`       |
| `NFTBLOCKD_POSTROUTING_CHAIN_NAME` | The name of the `nftables` postrouting chain in the blocklist table.                        | `postrouting`      |
| `NFTBLOCKD_BLOCKLIST_SET_NAME`     | The name of the blocklist set within the table.                                             | `blocklist_set`    |
| `NFTBLOCKD_ANTI_LOCKOUT_SET_NAME`  | The name of the blocklist set within the table.                                             | `anti_lockout_set` |


You can use these variables via an `.env` file for easy configuration:

```
NFTBLOCKD_IPV4_URL=https://example.com/ipv4-blocklist
NFTBLOCKD_IPV6_URL=https://example.com/ipv6-blocklist
NFTBLOCKD_INTERVAL=60
NFTBLOCKD_ANTI_LOCKOUT_IPV4=192.168.1.1 10.0.0.0/24
NFTBLOCKD_ANTI_LOCKOUT_IPV6=2001:db8::1
```

---

## System integration with `systemd`

To ensure `nftblockd` runs persistently on your system, even after reboots or network interruptions, you can configure
it as a `systemd` service. Below is an example `systemd` service configuration and a detailed explanation of the file
structure.

---

### Example `systemd` Service File

Save the following configuration as `/etc/systemd/system/nftblockd.service`:

```textmate
[Unit]
Description=Update IP blocklist for nftables with nftblockd
Wants=network-online.target nftables.service
After=network-online.target nftables.service

[Service]
Type=simple
Restart=always
RestartSec=60
EnvironmentFile=/opt/nftables/blocklist/nftblockd.env
ExecStart=/usr/local/sbin/nftblockd
ExecReload=/usr/local/sbin/nftblockd
ExecStopPost=/usr/local/sbin/nftblockd -d
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=sysinit.target
```

And create the **env** file.

```
cat /opt/nftables/blocklist/nftblockd.env
NFTBLOCKD_IPV4_URL=https://example.com/ipv4-blocklist
NFTBLOCKD_IPV6_URL=https://example.com/ipv6-blocklist
NFTBLOCKD_INTERVAL=60
```

---

### Steps to Enable and Start the Service

1. **Save the Service File**:
    - Save the example configuration as `/etc/systemd/system/nftblockd.service`.

2. **Reload `systemd`**:
    - Ensure `systemd` recognizes the new service:

```shell script
sudo systemctl daemon-reload
```

3. **Enable the Service**:
    - Automatically start the service at boot:

```shell script
sudo systemctl enable nftblockd
```

4. **Start the Service**:
    - Manually start the service:

```shell script
sudo systemctl start nftblockd
```

5. **Check Service Status**:
    - To verify it is running:

```shell script
sudo systemctl status nftblockd
```

6. **View Logs**:
    - Check logs using `journalctl`:

```shell script
journalctl -u nftblockd.service
```

---

### Example Logs

After enabling and running the service, you can analyze its logs using:

```shell script
journalctl -u nftblockd.service -n 100 -f
```

Example output:

```
May 23 12:16:13 <hostname> nftblockd[498270]: [2025-05-23T10:16:13Z INFO  nftblockd::blocklist] blocklist fetched from: http://localhost/ipv4.txt
May 23 12:16:13 <hostname> nftblockd[498270]: [2025-05-23T10:16:13Z WARN  nftblockd::subnet] invalid ip: 192.168.0.2/16; not a network
May 23 12:16:13 <hostname> nftblockd[498270]: [2025-05-23T10:16:13Z INFO  nftblockd::blocklist] blocklist fetched from: http://localhost/ipv6.txt
May 23 12:16:13 <hostname> nftblockd[498270]: [2025-05-23T10:16:13Z INFO  nftblockd] the `blocklist` table successfully loaded
May 23 12:16:13 <hostname> nftblockd[498270]: [2025-05-23T10:16:13Z INFO  nftblockd] finished
```

## Internals and Workflow

### High-Level Workflow:

1. **Fetch Blocklist**:
    - Fetches IPv4 and IPv6 blocklists from user-defined endpoints.

2. **Validate Blocklist**:
    - Parses the blocklists and ensures all subnets are well-formed and valid.

3. **Deduplicate Subnets**:
    - Removes redundant subnets using a trie-based algorithm. Ensures performance via prefix grouping.

4. **Transform for `nftables`**:
    - Converts validated subnets into `nftables`-compatible expressions.

5. **Apply Rules**:
    - Applies the blocklist to the configured `nftables` table and set, while respecting the anti-lockout rules.

### Code Structure:

- **`main.rs`**:
    - Handles CLI, environment parsing, and the main tool logic.
- **`subnet.rs`**:
    - Contains subnet parsing, blocklist validation, and subnet transformations.
- **`iptrie.rs`**:
    - Implements the trie-based deduplication algorithm for IPv4 and IPv6 subnets.
- **`network.rs`**:
    - Defines the abstraction for IPv4 and IPv6 blocklist networks.
- **`blocklist.rs`**:
    - Performs blocklist updating.
- **`anti_lockout.rs`**:
    - Ensures certain administrator-defined IPs cannot be blocked by mistake.
- **`nftables.rs`**:
    - APIs responsible for constructing and applying rules to `nftables`.

---

## Development

1. **Run Tests**:
   The project includes unit tests for validation, deduplication, and transformations.

```shell script
cargo test
```

2. **Static Analysis**:
   Use `clippy` to catch potential issues during development:

```shell script
cargo clippy --all-targets -- -D warnings 
```

3. **Formatting**:
   Format all Rust code prior to committing:

```shell script
cargo fmt
```

---

## Contribution

We welcome contributions to `nftblockd`. Feel free to open issues or submit pull requests. Follow the steps below to
contribute:

1. Fork this repository.
2. Create a feature branch (`git checkout -b feature-name`).
3. Commit your changes (`git commit -m 'Add a feature'`).
4. Push to your branch (`git push origin feature-name`).
5. Open a pull request.

---

## License

This project is licensed under the **MIT License**.

---

## Acknowledgements

This project uses the following third-party libraries:

- **`clap`**: For command-line argument parsing.
- **`ureq`**: For HTTP requests.
- **`log` and `env_logger`**: For logging support.
- **`ipnetwork`**: For managing IPv4/IPv6 subnets.
- **`itertools`**: For enhanced iterator functionality in Rust.

---

If you have further questions or want to report a bug, feel free to open an issue or reach out!
