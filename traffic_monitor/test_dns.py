from scapy.all import IP, UDP, DNS, DNSQR, send
import random
import string

print("Simulating malware DNS Exfiltration/DGA...")

for _ in range(80):
    # Generate a random, high-entropy 25-character subdomain
    subdomain = ''.join(random.choices(string.ascii_lowercase + string.digits, k=25))
    domain = f"{subdomain}.example.com"
    
    # Craft a raw UDP DNS Query directed at Google's public DNS
    packet = IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
    
    # Send directly to the network card, bypassing the Windows OS cache/DoH
    send(packet, verbose=0)

print("Done! Check your network monitor output.")