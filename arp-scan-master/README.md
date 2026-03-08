# arp-scan-fast

Fast, Windows-friendly ARP scanner leveraging multiprocessing and a TCP-nudge strategy to efficiently discover hosts on a local network.

## Features

- **Fast & Parallel**: Uses multiprocessing to rapidly probe missing targets in concurrent batches.
- **Windows-Friendly**: Works seamlessly on Windows by leveraging the native `arp -a` command. Avoids the strict requirement for Npcap or Scapy in the default mode.
- **TCP Nudge Strategy**: Performs short TCP `connect_ex` on specified ports (default: 80, 443, 22) to force the local OS to resolve the MAC address, then parses the local ARP cache.
- **No External Dependencies Required**: Runs entirely with standard Python libraries by default. Scapy is supported as an optional dependency for an even faster initial sweep.
- **Flexible Targets**: Supports single IPs, comma-separated lists, CIDR notation (e.g., `192.168.1.0/24`), and IP ranges (e.g., `192.168.1.1-192.168.1.100`).
- **Export Options**: Save scan results directly to CSV or JSON formats.

## Prerequisites

- **Python 3.7+**
- *(Optional)* `scapy` and Npcap/WinPcap if utilizing the `--use-scapy` flag.

## Usage

```bash
python arp-scan.py -t <TARGETS> [OPTIONS]
```

### Arguments

| Option | Description |
| :--- | :--- |
| `-t, --target` | **Required.** IP/CIDR, range `a-b`, or comma-separated list. |
| `--workers` | Number of parallel workers (default: `cpu_count() * 4`, minimum 8). |
| `--ports` | Comma-separated list of TCP ports to try in sequence for TCP nudging. Default: `80,443,22`. |
| `--timeout-ms` | TCP connection timeout per port in milliseconds. Default: `200`. |
| `--batch-size` | Number of connections to attempt concurrently before reading the ARP table again. Default: `200`. |
| `--csv` | Output file path to save results in CSV format. |
| `--json` | Output file path to save results in JSON format. |
| `-q, --quiet` | Quiet mode: suppress standard output reporting and banner. |
| `-v, --verbose` | Verbose mode: display highly detailed scan progress and batch results. |
| `--use-scapy` | Attempt an ultra-fast initial ARP sweep using Scapy (requires `scapy` and Npcap to be installed). |

### Examples

**Scan a standard `/24` CIDR subnet:**
```bash
python arp-scan.py -t 192.168.1.0/24
```

**Scan a specific IP range and save the output to CSV:**
```bash
python arp-scan.py -t 10.0.0.1-10.0.0.50 --csv results.csv
```

**Scan multiple subnets or lists with verbosity enabled:**
```bash
python arp-scan.py -t 192.168.1.0/24,192.168.2.0/24,10.10.10.5 -v
```

**Use Scapy for an initial fast sweep, then fallback to TCP Nudge:**
```bash
python arp-scan.py -t 192.168.1.0/24 --use-scapy
```

## How It Works

1. **Initial ARP Check**: Reads the local OS ARP table to see if target MAC addresses are already known.
2. **Optional Scapy Sweep**: If `--use-scapy` is passed, it sends rapid raw ARP requests (requires Npcap on Windows).
3. **TCP Nudging**: For any MAC addresses still missing, it performs lightweight TCP connections in parallel to designated ports. This operation forces the host OS network stack to initiate standard ARP requests to target IPs.
4. **ARP Re-Read**: Checks the local ARP table again to harvest newly discovered MAC addresses from the OS cache, providing the user with an accurate snapshot of active local hosts.
