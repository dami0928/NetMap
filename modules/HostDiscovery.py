import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


class hostdiscovery:

    def __init__(self,target,timeout=5) -> None:
        self.target = target
        self.timeout = timeout

    
    def target_list(self):
        targets = []
        for i in IPNetwork(self.target):
            targets.append(str(i))
        return targets


    def icmp_echo(self):
        pkt = IP(dst=str(ip))/ICMP()
        resp = sr1(pkt, timeout=self.timeout, verbose=0)  # sr1 waits for a response

        if resp and resp.haslayer(ICMP) and resp.getlayer(ICMP).type == 0:  # ICMP type 0 is Echo Reply
            return True
        else:
            return False
    

    def arp_ping(self):
        arp_request = ARP(pdst=self.target)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        
        arp_request_broadcast = broadcast/arp_request
        answered_list = srp(arp_request_broadcast, timeout=self.timeout, verbose=False)[0]
        
        for element in answered_list:
            return element[1].psrc


    def tcp_ack(self,port):
        pkt = IP(dst=self.target)/TCP(dport=port, flags="A")
        response = sr1(pkt, verbose=0, timeout=self.timeout)

        if response is None:
            return False
        elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
            return True
        else:
           return True


    def tcp_syn(self,port):
        pkt = IP(dst=self.target)/TCP(dport=port, flags="S")
        response = sr1(pkt, verbose=0, timeout=self.timeout)

        if response is None:
            return False
        elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            return True
        else:
            return True


    def check_timestamp(self):
        pkt = IP(dst=self.target)/ICMP(type=13)  # ICMP type 13 is Timestamp Request
        response = sr1(pkt, verbose=0, timeout=self.timeout)

        if response is None:
            return False
        elif response.haslayer(ICMP):
            return True
        else:
            return True


    def netmask(self):
        pkt = IP(dst=self.target)/ICMP(type=17)  # ICMP type 17 is Netmask Request
        response = sr1(pkt, verbose=0, timeout=self.timeout)

        if response is None:
            return False
        elif response.haslayer(ICMP):
            return True
        else:
            return True


    def traceroute(self,hops=20):
        rtt_ip = {}

        for ttl in range(1, hops + 1):
            # Create an ICMP Echo Request packet with the specified TTL
            pkt = IP(dst=self.target, ttl=ttl) / ICMP()
            response = sr1(pkt, verbose=0, timeout=self.timeout)

            if response is None:
                continue
            
            # Get the source IP of the response
            rtt = response.time - pkt.sent_time  
            rtt_ip[ttl] = {"ip":response.src,"rtt":rtt}

            # Stop if we reach the destination
            if response.src == self.target:
                rtt_ip[ttl] = {"ip":response.src,"rtt":rtt}
                break

        return rtt_ip
