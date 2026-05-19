"""
Wireshark MCP Server - wraps tshark.exe for packet capture and analysis.

Requires: Wireshark installed at C:/Program Files/Wireshark/tshark.exe
Run:      python server.py
"""

import asyncio
import json
import os
import subprocess
import tempfile
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

TSHARK = r"C:\Program Files\Wireshark\tshark.exe"


def run_tshark(*args: str, timeout: int = 30) -> tuple[str, str, int]:
    """Run tshark with the given args, return (stdout, stderr, returncode)."""
    result = subprocess.run(
        [TSHARK, *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return result.stdout, result.stderr, result.returncode


def clean_stderr(stderr: str) -> str:
    """Strip known harmless tshark warnings from stderr."""
    lines = [
        line for line in stderr.splitlines()
        if not line.startswith("tshark: Error loading table 'TLS Decrypt'")
        and line.strip()
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Server definition
# ---------------------------------------------------------------------------

app = Server("wireshark")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="list_interfaces",
            description="List all available network interfaces that tshark can capture on.",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        Tool(
            name="capture_packets",
            description=(
                "Capture live network packets on an interface and save to a pcap file. "
                "Stops after `duration` seconds or `count` packets (whichever comes first). "
                "Returns the path to the saved pcap file."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "interface": {
                        "type": "string",
                        "description": "Interface name or number from list_interfaces (e.g. '1' or 'Ethernet')",
                    },
                    "duration": {
                        "type": "integer",
                        "description": "Stop capture after this many seconds (default: 10, max: 60)",
                        "default": 10,
                    },
                    "count": {
                        "type": "integer",
                        "description": "Stop capture after this many packets (default: 100, max: 5000)",
                        "default": 100,
                    },
                    "capture_filter": {
                        "type": "string",
                        "description": "Optional BPF capture filter (e.g. 'tcp port 80')",
                    },
                    "output_file": {
                        "type": "string",
                        "description": "Optional output file path (.pcap). Uses a temp file if omitted.",
                    },
                },
                "required": ["interface"],
            },
        ),
        Tool(
            name="analyze_pcap",
            description=(
                "Read a pcap file and return a summary of packets. "
                "Optionally apply a Wireshark display filter. "
                "Returns up to `limit` packet lines."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "pcap_file": {
                        "type": "string",
                        "description": "Absolute path to the .pcap or .pcapng file",
                    },
                    "display_filter": {
                        "type": "string",
                        "description": "Optional Wireshark display filter (e.g. 'http', 'tcp.flags.syn==1')",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max number of packets to return (default: 100)",
                        "default": 100,
                    },
                },
                "required": ["pcap_file"],
            },
        ),
        Tool(
            name="get_protocol_stats",
            description="Get the protocol hierarchy statistics from a pcap file.",
            inputSchema={
                "type": "object",
                "properties": {
                    "pcap_file": {
                        "type": "string",
                        "description": "Absolute path to the pcap file",
                    },
                    "display_filter": {
                        "type": "string",
                        "description": "Optional display filter to apply before computing stats",
                    },
                },
                "required": ["pcap_file"],
            },
        ),
        Tool(
            name="get_field_values",
            description=(
                "Extract specific field values from packets in a pcap file. "
                "Useful for pulling out IPs, ports, DNS queries, HTTP hosts, etc."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "pcap_file": {
                        "type": "string",
                        "description": "Absolute path to the pcap file",
                    },
                    "fields": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "List of Wireshark field names to extract "
                            "(e.g. ['ip.src', 'ip.dst', 'tcp.dstport', 'http.host', 'dns.qry.name'])"
                        ),
                    },
                    "display_filter": {
                        "type": "string",
                        "description": "Optional display filter to apply first",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max rows to return (default: 200)",
                        "default": 200,
                    },
                },
                "required": ["pcap_file", "fields"],
            },
        ),
        Tool(
            name="get_conversations",
            description=(
                "Get conversation statistics from a pcap file. "
                "Shows top talkers and their byte/packet counts."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "pcap_file": {
                        "type": "string",
                        "description": "Absolute path to the pcap file",
                    },
                    "protocol": {
                        "type": "string",
                        "enum": ["eth", "ip", "tcp", "udp"],
                        "description": "Conversation type (default: ip)",
                        "default": "ip",
                    },
                    "display_filter": {
                        "type": "string",
                        "description": "Optional display filter",
                    },
                },
                "required": ["pcap_file"],
            },
        ),
        Tool(
            name="get_io_statistics",
            description=(
                "Get I/O throughput statistics from a pcap file. "
                "Shows packets/bytes per time interval."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "pcap_file": {
                        "type": "string",
                        "description": "Absolute path to the pcap file",
                    },
                    "interval": {
                        "type": "string",
                        "description": "Time interval (e.g. '1' for 1 second, '0.1' for 100ms). Default: '1'",
                        "default": "1",
                    },
                    "display_filter": {
                        "type": "string",
                        "description": "Optional display filter",
                    },
                },
                "required": ["pcap_file"],
            },
        ),
        Tool(
            name="follow_stream",
            description=(
                "Follow a TCP or UDP stream and return the reassembled data. "
                "You need to know the stream index (visible in analyze_pcap output as 'stream N')."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "pcap_file": {
                        "type": "string",
                        "description": "Absolute path to the pcap file",
                    },
                    "protocol": {
                        "type": "string",
                        "enum": ["tcp", "udp"],
                        "description": "Stream protocol",
                        "default": "tcp",
                    },
                    "stream_index": {
                        "type": "integer",
                        "description": "Stream index number (0-based)",
                        "default": 0,
                    },
                },
                "required": ["pcap_file"],
            },
        ),
        Tool(
            name="get_pcap_info",
            description="Get metadata about a pcap file: duration, packet count, file size, data link type, etc.",
            inputSchema={
                "type": "object",
                "properties": {
                    "pcap_file": {
                        "type": "string",
                        "description": "Absolute path to the pcap file",
                    },
                },
                "required": ["pcap_file"],
            },
        ),
        Tool(
            name="decode_packet",
            description=(
                "Decode a specific packet by number from a pcap file into full protocol detail (PDML-like text)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "pcap_file": {
                        "type": "string",
                        "description": "Absolute path to the pcap file",
                    },
                    "packet_number": {
                        "type": "integer",
                        "description": "1-based packet number to decode",
                    },
                },
                "required": ["pcap_file", "packet_number"],
            },
        ),
    ]


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------

@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        result = await _dispatch(name, arguments)
    except subprocess.TimeoutExpired:
        result = "Error: tshark timed out. Try a shorter capture duration or smaller file."
    except FileNotFoundError:
        result = f"Error: tshark not found at {TSHARK}. Check your Wireshark installation."
    except Exception as e:
        result = f"Error: {e}"

    return [TextContent(type="text", text=result)]


async def _dispatch(name: str, args: dict) -> str:
    if name == "list_interfaces":
        return _list_interfaces()
    elif name == "capture_packets":
        return await _capture_packets(args)
    elif name == "analyze_pcap":
        return _analyze_pcap(args)
    elif name == "get_protocol_stats":
        return _get_protocol_stats(args)
    elif name == "get_field_values":
        return _get_field_values(args)
    elif name == "get_conversations":
        return _get_conversations(args)
    elif name == "get_io_statistics":
        return _get_io_statistics(args)
    elif name == "follow_stream":
        return _follow_stream(args)
    elif name == "get_pcap_info":
        return _get_pcap_info(args)
    elif name == "decode_packet":
        return _decode_packet(args)
    else:
        return f"Unknown tool: {name}"


def _list_interfaces() -> str:
    stdout, stderr, rc = run_tshark("-D")
    if rc != 0:
        err = clean_stderr(stderr)
        return f"Failed to list interfaces:\n{err}" if err else "Failed to list interfaces."
    return stdout.strip() or "No interfaces found."


async def _capture_packets(args: dict) -> str:
    interface = args["interface"]
    duration = min(int(args.get("duration", 10)), 60)
    count = min(int(args.get("count", 100)), 5000)
    capture_filter = args.get("capture_filter", "")
    output_file = args.get("output_file", "")

    if not output_file:
        tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False, dir=tempfile.gettempdir())
        output_file = tmp.name
        tmp.close()

    cmd = [
        TSHARK,
        "-i", interface,
        "-a", f"duration:{duration}",
        "-c", str(count),
        "-w", output_file,
    ]
    if capture_filter:
        cmd += ["-f", capture_filter]

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        _, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=duration + 10)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return f"Capture timed out. Partial file may exist at: {output_file}"

    stderr_text = clean_stderr(stderr_bytes.decode(errors="replace"))
    file_size = Path(output_file).stat().st_size if Path(output_file).exists() else 0

    lines = [f"Capture complete: {output_file}"]
    lines.append(f"File size: {file_size:,} bytes")
    if stderr_text:
        lines.append(f"Notes: {stderr_text}")
    return "\n".join(lines)


def _analyze_pcap(args: dict) -> str:
    pcap = args["pcap_file"]
    display_filter = args.get("display_filter", "")
    limit = int(args.get("limit", 100))

    cmd = ["-r", pcap, "-n"]
    if display_filter:
        cmd += ["-Y", display_filter]

    stdout, stderr, rc = run_tshark(*cmd, timeout=60)
    stderr = clean_stderr(stderr)

    if rc != 0 and not stdout.strip():
        return f"Error reading pcap:\n{stderr}" if stderr else "Error reading pcap file."

    lines = stdout.strip().splitlines()
    total = len(lines)
    truncated = lines[:limit]
    result = "\n".join(truncated)
    if total > limit:
        result += f"\n\n[Showing {limit} of {total} packets. Use display_filter or increase limit.]"
    return result or "No packets matched."


def _get_protocol_stats(args: dict) -> str:
    pcap = args["pcap_file"]
    display_filter = args.get("display_filter", "")

    cmd = ["-r", pcap, "-q", "-z", "io,phs"]
    if display_filter:
        cmd += ["-Y", display_filter]

    stdout, stderr, rc = run_tshark(*cmd, timeout=60)
    stderr = clean_stderr(stderr)

    if rc != 0:
        return f"Error: {stderr}" if stderr else "Failed to compute protocol stats."
    return stdout.strip() or "No statistics generated."


def _get_field_values(args: dict) -> str:
    pcap = args["pcap_file"]
    fields = args["fields"]
    display_filter = args.get("display_filter", "")
    limit = int(args.get("limit", 200))

    if not fields:
        return "Error: fields list cannot be empty."

    cmd = ["-r", pcap, "-T", "fields", "-E", "separator=,", "-E", "header=y"]
    for f in fields:
        cmd += ["-e", f]
    if display_filter:
        cmd += ["-Y", display_filter]

    stdout, stderr, rc = run_tshark(*cmd, timeout=60)
    stderr = clean_stderr(stderr)

    if rc != 0 and not stdout.strip():
        return f"Error: {stderr}" if stderr else "Failed to extract fields."

    lines = stdout.strip().splitlines()
    total = len(lines)
    truncated = lines[:limit + 1]  # +1 for header
    result = "\n".join(truncated)
    if total > limit + 1:
        result += f"\n\n[Showing {limit} of {total - 1} data rows.]"
    return result or "No data matched."


def _get_conversations(args: dict) -> str:
    pcap = args["pcap_file"]
    protocol = args.get("protocol", "ip")
    display_filter = args.get("display_filter", "")

    cmd = ["-r", pcap, "-q", "-z", f"conv,{protocol}"]
    if display_filter:
        cmd += ["-Y", display_filter]

    stdout, stderr, rc = run_tshark(*cmd, timeout=60)
    stderr = clean_stderr(stderr)

    if rc != 0:
        return f"Error: {stderr}" if stderr else "Failed to compute conversations."
    return stdout.strip() or "No conversation data."


def _get_io_statistics(args: dict) -> str:
    pcap = args["pcap_file"]
    interval = args.get("interval", "1")
    display_filter = args.get("display_filter", "")

    cmd = ["-r", pcap, "-q", "-z", f"io,stat,{interval}"]
    if display_filter:
        cmd += ["-Y", display_filter]

    stdout, stderr, rc = run_tshark(*cmd, timeout=60)
    stderr = clean_stderr(stderr)

    if rc != 0:
        return f"Error: {stderr}" if stderr else "Failed to compute I/O stats."
    return stdout.strip() or "No I/O statistics."


def _follow_stream(args: dict) -> str:
    pcap = args["pcap_file"]
    protocol = args.get("protocol", "tcp")
    stream_index = int(args.get("stream_index", 0))

    cmd = ["-r", pcap, "-q", "-z", f"follow,{protocol},ascii,{stream_index}"]

    stdout, stderr, rc = run_tshark(*cmd, timeout=60)
    stderr = clean_stderr(stderr)

    if rc != 0:
        return f"Error: {stderr}" if stderr else "Failed to follow stream."
    return stdout.strip() or f"No data for {protocol} stream {stream_index}."


def _get_pcap_info(args: dict) -> str:
    pcap = args["pcap_file"]
    capinfos = Path(TSHARK).parent / "capinfos.exe"

    stdout, stderr, rc = run_tshark(
        *["-r", pcap, "-q", "-z", "io,phs"],
        timeout=30,
    )

    # Use capinfos for richer metadata
    try:
        result = subprocess.run(
            [str(capinfos), pcap],
            capture_output=True,
            text=True,
            timeout=15,
        )
        info_output = result.stdout.strip()
        if info_output:
            return info_output
    except Exception:
        pass

    # Fallback: basic file info from tshark
    stdout2, _, _ = run_tshark("-r", pcap, "-q", timeout=30)
    size = Path(pcap).stat().st_size if Path(pcap).exists() else 0
    return f"File: {pcap}\nSize: {size:,} bytes\n{stdout2.strip()}"


def _decode_packet(args: dict) -> str:
    pcap = args["pcap_file"]
    pkt_num = int(args["packet_number"])

    # Read just the one packet, verbose output
    cmd = ["-r", pcap, "-V", "-c", "1", f"--startfrom={pkt_num}", "-Y", f"frame.number=={pkt_num}"]
    stdout, stderr, rc = run_tshark(*cmd, timeout=30)
    stderr = clean_stderr(stderr)

    if not stdout.strip():
        # Fallback: use frame filter without --startfrom (not all tshark builds support it)
        cmd2 = ["-r", pcap, "-V", "-Y", f"frame.number=={pkt_num}"]
        stdout, stderr, rc = run_tshark(*cmd2, timeout=30)
        stderr = clean_stderr(stderr)

    if not stdout.strip():
        return f"Packet {pkt_num} not found or error: {stderr}"
    return stdout.strip()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
