from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.error import Scapy_Exception
from collections import Counter


def read_pcap(file):
    try:
        packets = rdpcap(file)

    except Scapy_Exception:
        return {
            "status": "error",
            "message": "Invalid or unsupported PCAP file."
        }

    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }

    protocol_count = Counter()
    source_ips = Counter()
    destination_ips = Counter()

    suspicious = []

    tcp_count = 0
    udp_count = 0
    icmp_count = 0
    arp_count = 0
    dns_count = 0
    http_count = 0

    for packet in packets:

        if IP in packet:
            source_ips[packet[IP].src] += 1
            destination_ips[packet[IP].dst] += 1

        if TCP in packet:

            tcp_count += 1
            protocol_count["TCP"] += 1

            if packet[TCP].sport == 80 or packet[TCP].dport == 80:
                http_count += 1
                protocol_count["HTTP"] += 1

            if packet[TCP].sport == 53 or packet[TCP].dport == 53:
                dns_count += 1
                protocol_count["DNS"] += 1

            if packet[TCP].flags == "S":
                suspicious.append("TCP SYN packet")

        elif UDP in packet:

            udp_count += 1
            protocol_count["UDP"] += 1

            if packet[UDP].sport == 53 or packet[UDP].dport == 53:
                dns_count += 1
                protocol_count["DNS"] += 1

        elif ICMP in packet:

            icmp_count += 1
            protocol_count["ICMP"] += 1

        elif ARP in packet:

            arp_count += 1
            protocol_count["ARP"] += 1

    recommendations = []

    if tcp_count > 500:
        recommendations.append("High TCP traffic detected.")

    if icmp_count > 50:
        recommendations.append("Possible ping sweep detected.")

    if dns_count > 100:
        recommendations.append("High DNS traffic detected.")

    if len(suspicious) > 100:
        recommendations.append("Possible SYN flood or Port Scan.")

    if not recommendations:
        recommendations.append("No suspicious activity detected.")

    if len(suspicious) > 100:
        threat = "High"
    elif len(suspicious) > 20:
        threat = "Medium"
    else:
        threat = "Low"

    return {
        "status": "success",
        "Total Packets": len(packets),
        "Threat Level": threat,
        "Protocols": dict(protocol_count),
        "Top Source IPs": dict(source_ips.most_common(5)),
        "Top Destination IPs": dict(destination_ips.most_common(5)),
        "Recommendations": recommendations
    }