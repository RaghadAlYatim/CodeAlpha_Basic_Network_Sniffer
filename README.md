# CodeAlpha_Basic_Network_Sniffer code
A Python-based packet sniffer that filters network traffic by certain protocols (TCP, UDP, ICMP) and records it on a designated interface. provides an optional verbose mode for real-time monitoring and logs information about every packet, including source and destination IP addresses and ports.

# Table of Contents
. Installation
. Usage
. Features
. Output Example
#Installation
on your kali linux terminal
. git clone https://github.com/RaghadAlYatim/CodeAlpha_Basic_Network_Sniffer.git
. cd CodeAlpha_Basic_Network_Sniffer
. pip install scapy
. chmod +x codeAlpha_Packet_Sniffer.py

# Usage
sudo python codeAlpha_Packet_Sniffer.py <interface> <protocols> [verbose]
EXAMPLE: sudo python sniffer.py eth0 TCP,UDP verbose

# The features
. records and keeps track of network packets for chosen protocols.
. Protocol-type filters include TCP, UDP, and ICMP.
. verbose mode for displaying packet details in real time.
. smoothly shuts off using a SIGINT signal (such as Ctrl+C).

#Output Example
![Screenshot of packet sniffer code run and results](https://github.com/user-attachments/assets/db339cba-6c45-4804-b0b6-30df8e1c0984)
![Screenshot of file logged with packets information during sniffing](https://github.com/user-attachments/assets/59c9d17b-c3bf-4bd7-a8fe-9e0e62bbd708)
