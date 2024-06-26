from scapy.all import sniff, wrpcap
from scapy.layers.inet import TCP

class PacketAnalyzer:
    def __init__(self, count=10, filter_rule="tcp"):
        self.count = count
        self.filter_rule = filter_rule

    def capture_packets(self):
        try:
            return sniff(count=self.count)
        except Exception as e:
            print(f"Error capturing packets: {e}")

    def analyze_packet(self, packet):
        print(f"Packet: {packet.summary()}")
        print(f"Protocol: {packet.payload.name}")
        try:
            print(f"Source: {packet[0][1].src}, Destination: {packet[0][1].dst}")
        except IndexError:
            print("Packet has no IP layer")

    def inspect_packet(self, packet):
        packet.show()

    def filter_traffic(self):
        return sniff(filter=self.filter_rule, count=self.count)

    def detect_issues(self, packet):
        if packet.haslayer(TCP) and (packet[TCP].flags == "R"):  # Reset flag
            print(f"Reset packet detected: {packet.summary()}")

    def save_packets(self, packets, filename="captured_packets.pcap"):
        wrpcap(filename, packets)

    def run(self):
        print("Capturing packets...")
        packets = self.capture_packets()

        print("\nAnalyzing packets...")
        for packet in packets:
            self.analyze_packet(packet)
            self.inspect_packet(packet)
            self.detect_issues(packet)

        print("\nFiltering TCP traffic...")
        filtered_packets = self.filter_traffic()
        for packet in filtered_packets:
            self.analyze_packet(packet)

        print("\nSaving packets to file...")
        self.save_packets(packets, filename="captured_packets.pcap")

if __name__ == "__main__":
    analyzer = PacketAnalyzer(count=10, filter_rule="tcp")
    analyzer.run()
