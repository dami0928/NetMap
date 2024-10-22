import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import socks
import socket


class ids:

    def __init__(self) -> None:
        pass


    def pkt_frag(pkt,fragsize=8):
        fragments = fragment(packet, fragsize=fragsize)
        for frag in fragments:
            send(frag)
    

    def decoy(ip,pkt):
        for i in ip:
            pkt[IP].src = i
            yield pkt


    def spoof_ip(ip,pkt):
        pkt[IP].src = ip

    def spoof_port(p,pkt):
        pkt[TCP].sport = p

    def append_data(pkt,data):
        pkt += (data)
        return pkt
    
    def ttl(pkt,n):
        pkt[IP].ttl = n

    def proxy(pkt,host,port):
        socks.set_default_proxy(socks.SOCKS5, host, port)  
        socket.socket = socks.socksocket

    def badsum(pkt):
        pass

    def check_zombie_host(target):
        response1 = sr1(IP(dst=target)/TCP(dport=80, flags="SA"), timeout=1, verbose=0)
        if response1 is None:
            return False

        initial_ip_id = response1[IP].id

        response2 = sr1(IP(dst=target)/TCP(dport=80, flags="SA"), timeout=1, verbose=0)
        if response2 is None:
            return False

        new_ip_id = response2[IP].id

        if new_ip_id == initial_ip_id + 1:
            return True
        else:
            return False