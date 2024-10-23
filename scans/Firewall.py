import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

class Firewall:

    sport = RandShort()

    def __init__(self,port,target,timeout=5) -> None:
        self.port = port
        self.target = target
        self.timeout = timeout


    def xmas(self):
        pkt = IP(dst=self.target)/TCP(dport=self.port,flags='FPU')
        ans = sr1(pkt,verbose=False,timeout=self.timeout)
        if(ans == None):
            return True
        elif(ans.haslayer(TCP)):
            if(ans.getlayer(TCP).flags == 0x14):
                return False
        elif(ans.haslayer(ICMP).type == 3) and int(ans.getlayer(ICMP).code) in [1,2,3,9,10,13]:
            return False
        else:
            return "Filtered"


    def fin(self):
        pkt = IP(dst=self.target)/TCP(dport=self.port,flags='F')
        ans = sr1(pkt,verbose=False,timeout=self.timeout)
        if(ans == None):
            return True
        elif(ans.haslayer(TCP)):
            if(ans.getlayer(TCP).flags == 0x14):
                return False
        elif(ans.haslayer(ICMP).type == 3) and int(ans.getlayer(ICMP).code) in [1,2,3,9,10,13]:
            return False
        else:
            return "Filtered"


    def null(self):
        pkt = IP(dst=self.target)/TCP(dport=self.port,flags='')
        ans = sr1(pkt,verbose=False,timeout=self.timeout)
        if(ans == None):
            return True
        elif(ans.haslayer(TCP)):
            if(ans.getlayer(TCP).flags == 0x14):
                return False
        elif(ans.haslayer(ICMP).type == 3) and int(ans.getlayer(ICMP).code) in [1,2,3,9,10,13]:
            return False
        else:
            return "Filtered"


    def tcp_ack(self):
        pkt = IP(dst=self.target)/TCP(dport=self.port,flags='A')
        ans = sr1(pkt,verbose=False,timeout=self.timeout)
        if(ans == None):
            return True
        elif(ans.haslayer(TCP)):
            if(ans.getlayer(TCP).flags == 0x4):
                return False
        elif(ans.haslayer(ICMP).type == 3) and int(ans.getlayer(ICMP).code) in [1,2,3,9,10,13]:
            return True
        else:
            return "Filtered"
        

        
    
