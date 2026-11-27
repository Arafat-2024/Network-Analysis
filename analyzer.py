# Import CSV to create CSV reports
import csv

# Import OS to check files and create folders
import os

# Import Counter and defaultdict for counting network information
from collections import Counter, defaultdict

# Import datetime to format packet timestamps
from datetime import datetime

# Import required Scapy components for reading and analyzing packets
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS

# Define the location of the captured network traffic
PCAP_FILE = "captures/network_traffic.pcap"

# Define the folder where analysis reports will be saved
REPORT_DIR = "reports"

# Define the threshold for possible port-scan detection
PORT_SCAN_THRESHOLD = 10

# Check whether the PCAP file exists
if not os.path.exists(PCAP_FILE):

    print("Error: PCAP file not found!")

    print("Please place your capture inside the captures folder.")

    exit()

# Read all packets from the PCAP file
try:

    packets = rdpcap(PCAP_FILE)

    # Display the number of captured packets
    print("Total captured packets:", len(packets))

except Exception as error:

    # Display an error if the PCAP file cannot be read
    print("Unable to read PCAP file:", error)

    exit()

# Count the number of packets for each protocol
protocol_counts = Counter()

# Count packets sent by each source IP
source_counts = Counter()

# Count packets received by each destination IP
destination_counts = Counter()

# Store DNS query counts
dns_queries = Counter()

# Store unique SYN destination ports for each source-destination pair
syn_ports_by_pair = defaultdict(set)

# Store individual packet information for the CSV report
packet_rows = []

# Count IPv4 packets
ipv4_count = 0


# Loop through every packet in the PCAP file
for packet in packets:

    # Check whether the packet contains an IPv4 layer
    if not packet.haslayer(IP):

        continue

    # Extract the IPv4 layer
    ip_packet = packet[IP]

    # Get source and destination IP addresses
    source_ip = ip_packet.src
    destination_ip = ip_packet.dst

    # Increase the IPv4 packet count
    ipv4_count += 1

    # Initialize port values
    source_port = ""
    destination_port = ""

    # Identify TCP packets
    if packet.haslayer(TCP):

        protocol = "TCP"

        # Extract TCP source and destination ports
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

        # Convert TCP flags into an integer
        tcp_flags = int(packet[TCP].flags)

        # Check for an initial SYN packet without ACK
        is_initial_syn = (tcp_flags & 0x02) and not (tcp_flags & 0x10)

        # Store destination ports for possible scan detection
        if is_initial_syn:

            syn_ports_by_pair[(source_ip, destination_ip)].add(destination_port)

    # Identify UDP packets
    elif packet.haslayer(UDP):

        protocol = "UDP"

        # Extract UDP source and destination ports
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    # Identify ICMP packets
    elif packet.haslayer(ICMP):

        protocol = "ICMP"

    # Identify other IPv4 packets
    else:

        protocol = "OTHER"

    # Count the identified protocol
    protocol_counts[protocol] += 1

    # Count source IP addresses
    source_counts[source_ip] += 1

    # Count destination IP addresses
    destination_counts[destination_ip] += 1

    # Extract DNS queries from DNS request packets
    if packet.haslayer(DNS):

        dns_packet = packet[DNS]

        # Check whether this is a DNS query
        if dns_packet.qr == 0 and dns_packet.qd is not None:

            # Extract the requested domain name
            query_name = dns_packet.qd.qname

            # Convert bytes into readable text
            if isinstance(query_name, bytes):

                query_name = query_name.decode("utf-8", errors="ignore")

            # Remove the final dot and count the DNS query
            dns_queries[query_name.rstrip(".")] += 1

    # Extract packet timestamp
    timestamp = datetime.fromtimestamp(
        float(packet.time)
    ).strftime("%Y-%m-%d %H:%M:%S")

    # Store packet information
    packet_rows.append({

        "Timestamp": timestamp,

        "Source IP": source_ip,

        "Destination IP": destination_ip,

        "Protocol": protocol,

        "Source Port": source_port,

        "Destination Port": destination_port,

        "Packet Length": len(packet)

    })


    # Create a list to store possible security alerts
security_alerts = []

# Check every source and destination IP pair
for ip_pair, destination_ports in syn_ports_by_pair.items():

    # Extract source IP address
    source_ip, destination_ip = ip_pair

    # Count unique destination ports
    unique_port_count = len(destination_ports)

    # Check whether the number of ports reaches the threshold
    if unique_port_count >= PORT_SCAN_THRESHOLD:

        # Create a possible port-scan alert
        alert = (
            f"Possible TCP SYN port-scan pattern: "
            f"{source_ip} sent SYN packets to "
            f"{unique_port_count} unique ports on {destination_ip}"
        )

        # Store the alert
        security_alerts.append(alert)


# Create the reports folder if it does not exist
os.makedirs(REPORT_DIR, exist_ok=True)

# Define the CSV report file path
csv_file = os.path.join(REPORT_DIR, "packet_analysis.csv")

# Define CSV column names
fieldnames = [
    "Timestamp",
    "Source IP",
    "Destination IP",
    "Protocol",
    "Source Port",
    "Destination Port",
    "Packet Length"
]

# Open the CSV file
with open(csv_file, "w", newline="", encoding="utf-8") as file:

    # Create CSV writer
    writer = csv.DictWriter(file, fieldnames=fieldnames)

    # Write column headings
    writer.writeheader()

    # Write all analyzed packet information
    writer.writerows(packet_rows)

# Display the report location
print("Packet CSV report generated:", csv_file)



# Create an empty list for the summary report
report_lines = []

# Add general packet information
report_lines.append("NETWORK TRAFFIC ANALYSIS REPORT")

report_lines.append("=" * 40)

report_lines.append(f"Total Captured Packets: {len(packets)}")

report_lines.append(f"IPv4 Packets Analyzed: {ipv4_count}")


# Add protocol analysis
report_lines.append("\nPROTOCOL ANALYSIS")

report_lines.append("-" * 40)

for protocol, count in protocol_counts.most_common():

    report_lines.append(f"{protocol}: {count}")


# Add top source IP addresses
report_lines.append("\nTOP SOURCE IP ADDRESSES")

report_lines.append("-" * 40)

for ip, count in source_counts.most_common(5):

    report_lines.append(f"{ip}: {count} packets")


# Add top destination IP addresses
report_lines.append("\nTOP DESTINATION IP ADDRESSES")

report_lines.append("-" * 40)

for ip, count in destination_counts.most_common(5):

    report_lines.append(f"{ip}: {count} packets")


# Add DNS analysis
report_lines.append("\nDNS QUERY ANALYSIS")

report_lines.append("-" * 40)

for domain, count in dns_queries.most_common(10):

    report_lines.append(f"{domain}: {count} queries")


# Add security alerts
report_lines.append("\nSECURITY ALERTS")

report_lines.append("-" * 40)

if security_alerts:

    for alert in security_alerts:

        report_lines.append(alert)

else:

    report_lines.append("No possible port-scan patterns detected.")


# Save the report as a text file
report_file = os.path.join(REPORT_DIR, "traffic_summary.txt")

with open(report_file, "w", encoding="utf-8") as file:

    file.write("\n".join(report_lines))


# Display report information
print("\nAnalysis completed successfully!")

print("Summary report generated:", report_file)