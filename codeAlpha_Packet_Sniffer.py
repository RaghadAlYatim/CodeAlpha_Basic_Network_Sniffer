import sys
import os
import signal
from scapy.all import *
from datetime import datetime

# This function is for each packet monitoring
def handle_packet(packet, log, protocol_type, verbose):
    # These functions to see if the packet corresponds to any of the chosen protocols
    if "TCP" in protocol_type and packet.haslayer(TCP):
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif "UDP" in protocol_type and packet.haslayer(UDP):
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    elif "ICMP" in protocol_type and packet.haslayer(ICMP):
        protocol = "ICMP"
        src_port = None
        dst_port = None
    else:
        return  # Skip packet if it doesn't fit any of the chosen protocols

    # This is to retrieve timestamps and IP addresses
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # This will log packet details/information
    log_entry = f"{timestamp} - {protocol} Connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n"
    log.write(log_entry)

    # If verbose mode is enabled, print the log item.
    if verbose:
        print(log_entry.strip())

# A signal handler for smooth shutdown
def signal_handler(sig, frame, log):
    print("\n[+] Quitting... Closing log file.")
    log.close()
    sys.exit(0)

# This is the main function packet sniffing initiation
def main(interface, protocol_type, verbose=False, log_file_size=1024*1024):
    # This is to see if you are running as root
    if os.geteuid() != 0:
        print("Please run the script as root to avoid permission denial errors.")
        sys.exit(1)

    # This is to create a log file and establishing signal handling
    logfile_name = f"Packetsniffer_{interface}_log.txt"
    log = open(logfile_name, 'w')
    signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(sig, frame, log))

    # This will start packet sniffing on the chosen interface
    print(f"[+] Starting packet sniffing on {interface}...")
    try:
        sniff(iface=interface, prn=lambda pkt: handle_packet(pkt, log, protocol_type, verbose), store=0)
    except PermissionError:
        print("Permission denied: Make sure you have root privileges.")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        log.close()

# This represents the entry point
if __name__ == "__main__":
    # Interpretation of command-line arguments
    if len(sys.argv) < 3:
        print("Usage: python sniffer_file.py <interface> <protocol_type> [verbose]")
        sys.exit(1)

    interface = sys.argv[1]
    protocol_type = sys.argv[2].upper().split(",")  # Here comma is used to separate list of protocols
    verbose = len(sys.argv) == 4 and sys.argv[3].lower() == "verbose"

    main(interface, protocol_type, verbose)
