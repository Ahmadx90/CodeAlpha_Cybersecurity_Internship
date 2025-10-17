#!/usr/bin/env python3
"""
Basic Network Sniffer (Scapy)
- Captures live packets
- Prints: timestamp, src/dst IPs, protocol, ports (if applicable), payload preview
- Saves captured packets into pcap file optionally
"""
import os
import sys
import time
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, wrpcap, conf
from utils import protocol_name, pretty_payload
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()

# OUTPUT directory for saved captures
OUTPUT_DIR = "saved_captures"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Number of packets to store in memory before writing to disk (or None to not save)
SAVE_TO_PCAP = True
PCAP_FILENAME = os.path.join(OUTPUT_DIR, f"capture_{int(time.time())}.pcap")
_saved_packets = []

packet_count = [0]  # Mutable counter for packet numbering


def packet_summary(pkt):
    packet_count[0] += 1
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    if IP in pkt:
        ip = pkt[IP]
        src = ip.src
        dst = ip.dst
        proto = protocol_name(ip.proto)
        sport = "-"
        dport = "-"
        if TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif UDP in pkt:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

        payload_preview = pretty_payload(pkt)

        # Create a styled table for key details
        table = Table(show_header=True, header_style="bold magenta", box=box.MINIMAL, expand=True)
        table.add_column("Field", style="cyan bold", justify="right", width=15)
        table.add_column("Value", style="white", justify="left")

        # Add packet number row
        table.add_row("", Text(f"#{packet_count[0]}", style="bold yellow"))

        table.add_row(Text("Time", style="bold"), Text(ts, style="green"))
        table.add_row(Text("Source IP", style="bold"), Text(src, style="bright_green"))
        table.add_row(Text("Source Port", style="bold"), Text(str(sport), style="bright_green"))
        table.add_row(Text("Destination IP", style="bold"), Text(dst, style="bright_red"))
        table.add_row(Text("Destination Port", style="bold"), Text(str(dport), style="bright_red"))
        table.add_row(Text("Protocol", style="bold"), Text(proto, style="yellow"))

        # Payload is shown fully below the table for better readability
        payload_text = Text("Payload:", style="bold") + Text("\n" + payload_preview, style="dim white")

        # Combine table and payload in a group for the panel
        from rich.console import Group
        content = Group(table, payload_text)

        console.print(
            Panel(content, title="Packet Captured", subtitle=ts, border_style="blue", expand=True, box=box.ASCII2))
        console.print()  # Blank line separator for next packet
    else:
        console.print(Panel(f"Non-IP packet captured at {ts}", border_style="yellow", box=box.ASCII2))


def handle_packet(pkt):
    try:
        packet_summary(pkt)
        if SAVE_TO_PCAP:
            _saved_packets.append(pkt)
            # flush to disk every 50 packets
            if len(_saved_packets) >= 50:
                wrpcap(PCAP_FILENAME, _saved_packets, append=True)
                _saved_packets.clear()
    except Exception as e:
        console.print(f"[red]Error processing packet:[/] {e}")


def on_exit():
    # write remaining packets
    if SAVE_TO_PCAP and _saved_packets:
        console.print(f"[green]Writing remaining {len(_saved_packets)} packets to {PCAP_FILENAME}[/]")
        wrpcap(PCAP_FILENAME, _saved_packets, append=True)


def main():
    console.print("[bold magenta]Basic Network Sniffer (Scapy)[/]")
    console.print("[blue]Make sure PyCharm/this script is running as Administrator and Npcap is installed.[/]\n")
    # Try to use pcap backend on Windows (Scapy)
    try:
        conf.use_pcap = True
    except Exception:
        pass

    console.print(f"[white]Saving capture to:[/] {PCAP_FILENAME}\n")
    try:
        # sniff() runs until Ctrl+C
        sniff(prn=handle_packet, store=False)  # remove filter for all protocols
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Capture stopped by user (Ctrl+C)[/]")
    except PermissionError:
        console.print("[red]PermissionError: Are you running as Administrator?[/]")
    except Exception as e:
        console.print(f"[red]Unexpected error:[/] {e}")
    finally:
        on_exit()
        console.print("[green]Exiting.[/]")


if __name__ == "__main__":
    main()