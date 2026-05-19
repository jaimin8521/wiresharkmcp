# 🦈 Wireshark MCP Server

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server that wraps **tshark** (Wireshark's CLI) to give Claude the ability to capture and analyze network traffic directly in conversation.

## Demo

Ask Claude things like:
- *"Capture 30 seconds of traffic on my Wi-Fi"*
- *"What are the top talkers in this pcap?"*
- *"Show me all DNS queries in the capture"*
- *"Follow TCP stream 0 and tell me what's in it"*
- *"Decode packet #42 in full detail"*

## Requirements

- **Windows** (tested on Windows 10/11)
- **Wireshark 4.x** installed at `C:\Program Files\Wireshark\` (includes tshark.exe)
- **Python 3.10+**
- **Npcap** (installed with Wireshark) for live capture
- **Admin privileges** for live packet capture

## Installation

### 1. Clone the repo
```bash
git clone https://github.com/YOUR_USERNAME/wireshark-mcp.git
cd wireshark-mcp
```

### 2. Install Python dependencies
```bash
pip install -r requirements.txt
```

### 3. Register with Claude Code

Add this to your `~/.claude.json` under the `mcpServers` key:

```json
{
  "mcpServers": {
    "wireshark": {
      "command": "C:\\Path\\To\\python.exe",
      "args": ["C:\\Path\\To\\wireshark-mcp\\server.py"]
    }
  }
}
```

Or use the Claude Code CLI:
```bash
claude mcp add wireshark python C:\Path\To\wireshark-mcp\server.py
```

### 4. Restart Claude Code

After restarting, type `/mcp` to confirm the `wireshark` server is connected.

## Tools

| Tool | Description |
|------|-------------|
| `list_interfaces` | List all network interfaces available for capture |
| `capture_packets` | Live capture on an interface, saves to pcap file |
| `analyze_pcap` | Summarize packets in a pcap with optional display filter |
| `get_protocol_stats` | Protocol hierarchy breakdown (% of traffic per protocol) |
| `get_field_values` | Extract specific fields (IPs, ports, DNS names, HTTP hosts…) |
| `get_conversations` | Top talkers by IP/TCP/UDP with byte/packet counts |
| `get_io_statistics` | Throughput over time intervals |
| `follow_stream` | Reassemble and read a TCP/UDP stream |
| `get_pcap_info` | File metadata: duration, packet count, data link type |
| `decode_packet` | Full verbose protocol decode of a single packet |

## Usage with MCP Inspector (optional)

For a visual UI to call tools manually:

```bash
# Requires Node.js
npx @modelcontextprotocol/inspector python C:\Path\To\wireshark-mcp\server.py
```

Then open `http://localhost:6274` in your browser.

## Configuration

By default the server looks for tshark at:
```
C:\Program Files\Wireshark\tshark.exe
```

To change this, edit the `TSHARK` variable at the top of `server.py`:
```python
TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
```

## Notes

- **Live capture requires admin/elevated privileges** on Windows (run Claude Code as Administrator)
- Capture duration is capped at **60 seconds** and packet count at **5,000** for safety
- All pcap analysis tools work without admin privileges

## License

MIT
