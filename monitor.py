from scapy.all import sniff, ICMP, IP
import sqlite3
from datetime import datetime

# Connect to database
conn = sqlite3.connect("database.db", check_same_thread=False)
cursor = conn.cursor()

# Create packets table if not exists
cursor.execute("""
    CREATE TABLE IF NOT EXISTS packets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_ip TEXT,
        destination_ip TEXT,
        protocol TEXT,
        packet_size INTEGER,
        icmp_type INTEGER,
        time TEXT
    )
""")

# Create blocked_ips table if not exists
cursor.execute("""
    CREATE TABLE IF NOT EXISTS blocked_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT UNIQUE,
        reason TEXT,
        blocked_time TEXT
    )
""")

conn.commit()

def process_packet(packet):
    if packet.haslayer(ICMP):
        # Only ICMP Echo Request
        if packet[ICMP].type == 8:
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst
            protocol = "ICMP"
            packet_size = len(packet)
            icmp_type = packet[ICMP].type

            current_time = datetime.now().strftime("%d-%m-%Y %I:%M:%S %p")

            # Check if source IP is blocked
            cursor.execute("SELECT * FROM blocked_ips WHERE ip_address=?", (source_ip,))
            is_blocked = cursor.fetchone()

            if not is_blocked:
                cursor.execute("""
                INSERT INTO packets
                (
                    source_ip,
                    destination_ip,
                    protocol,
                    packet_size,
                    icmp_type,
                    time
                )
                VALUES
                (?, ?, ?, ?, ?, ?)
                """,
                (
                    source_ip,
                    destination_ip,
                    protocol,
                    packet_size,
                    icmp_type,
                    current_time
                ))

                conn.commit()

                print("\n===================================")
                print(" ICMP PACKET DETECTED ")
                print("===================================")
                print(f"Time        : {current_time}")
                print(f"Source IP   : {source_ip}")
                print(f"Target IP   : {destination_ip}")
                print(f"Protocol    : {protocol}")
                print(f"Packet Size : {packet_size} Bytes")
                print(f"ICMP Type   : {icmp_type}")
                print("===================================")
            else:
                print(f"\n[PACKET DROPPED] Blocked IP: {source_ip}")

print("Listening for ICMP Packets...")

sniff(
    filter="icmp",
    prn=process_packet,
    store=False
)
