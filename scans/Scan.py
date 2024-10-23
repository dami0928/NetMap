import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
import threading


class scans:

    sport = RandShort()
    thread = []

    def __init__(self,port,target,timeout=5) -> None:
        self.port = port
        self.target = target
        self.timeout = timeout

    
    def tcp_conn(self):
        pkt = IP(dst=self.target)/TCP(sport=self.sport,dport=self.port,flags='S')
        ans = sr1(pkt,verbose=False,timeout=self.timeout)
        if(ans == None):
            return False
        elif(ans.haslayer(TCP)):
            if(ans.getlayer(TCP).flags == 0x12):
                pkt = IP(dst=self.target)/TCP(sport=self.sport,dport=self.port,flags='AR')
                sr1(pkt,verbose=False,timeout=self.timeout)
                return True
            elif(ans.getlayer(TCP).flags == 0x14):
                return False
        else:
            return False


    def tcp_stealth(self):
        pkt = IP(dst=self.target)/TCP(sport=self.sport,dport=self.port,flags='S')
        ans = sr1(pkt,verbose=False,timeout=self.timeout)
        if(ans == None):
            return False
        elif(ans.haslayer(TCP)):
            if(ans.getlayer(TCP).flags == 0x12):
                pkt = IP(dst=self.target)/TCP(sport=self.sport,dport=self.port,flags='R')
                sr1(pkt,verbose=False,timeout=self.timeout)
                return True
            elif(ans.getlayer(TCP).flags == 0x14):
                return False
        elif(ans.haslayer(ICMP).type == 3) and int(ans.getlayer(ICMP).code) in [1,2,3,9,10,13]:
            return "Filtered"
        else:
            return False
        

    def tcp_window(self):
        pkt = IP(dst=self.target)/TCP(sport=self.sport,dport=self.port,flags='A')
        ans = sr1(pkt,verbose=False,timeout=self.timeout)
        if(ans == None):
            return False
        elif(ans.haslayer(TCP)):
            if(ans.getlayer(TCP).window > 0):
                return True
            elif(ans.getlayer(TCP).window == 0):
                return False
            

    def ftp_bounce(self,ftp_server):
        # Connect to the FTP server
        ftp_request = f'PORT {self.target.replace(".", ",")},{self.port//256},{self.port%256}\r\n'
        
        # Create TCP connection to FTP server (assuming port 21)
        ftp_pkt = IP(dst=ftp_server)/TCP(dport=21,flags='S')
        syn_ack = sr1(ftp_pkt, timeout=self.timeout, verbose=0) # SYN-ACK
        
        if syn_ack is None or syn_ack[TCP].flags != 'SA':
            return False
        
        # Send FTP PORT command to request target connection
        ftp_data = IP(dst=ftp_server)/TCP(dport=21, sport=syn_ack[TCP].sport, seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq+1)/Raw(load=ftp_request)
        ftp_response = sr1(ftp_data, timeout=self.timeout, verbose=0)  # Response ignored
        
        if ftp_response is None:
            return False
        
        # Attempt to scan port
        probe_pkt = IP(dst=ftp_server)/TCP(dport=self.port,flags='S')
        response = sr1(probe_pkt, timeout=self.timeout, verbose=0)
        
        if response is None:
            return False
        elif response[TCP].flags == 'SA':
            return True
        elif response[TCP].flags == 'RA':
            return False
        


    def resolve_hostname(hostname, dns_server="8.8.8.8"):
        # Build the DNS request packet
        dns_query = IP(dst=dns_server)/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname=hostname))
        
        # Send the DNS query and wait for a response
        response = sr1(dns_query, verbose=0, timeout=5)
        
        if response and response.haslayer(DNS) and response[DNS].ancount > 0:
            # Extract the IP address from the response
            for i in range(response[DNS].ancount):
                answer = response[DNS].an[i]
                if answer.type == 1:  # DNS type A (IPv4 address)
                    return answer.rdata
        else:
            return False
        return None



    def reverse_dns_lookup(hostname,dns_server="8.8.8.8"):
        try:
            # Convert the IP to reverse DNS format (e.g., 1.1.1.1 -> 1.1.1.1.in-addr.arpa)
            reverse_ip = '.'.join(reversed(hostname.split('.'))) + ".in-addr.arpa"
            
            # Create a DNS query packet
            dns_query = IP(dst=dns_server) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=reverse_ip, qtype="PTR"))
            
            # Send the DNS query and get the response
            response = sr1(dns_query, verbose=0, timeout=2)
            
            # Check if we got a valid response with an answer
            if response and response.haslayer(DNS) and response[DNS].ancount > 0:
                # Extract the domain name from the DNS response
                domain_name = response[DNS].an.rdata.decode()  # Extract the PTR record
                return domain_name
            else:
                return False

        except Exception as e:
            return e



def packet_trace(target):
    def packet_callback(packet):
        # Check if the packet is related to the target IP
        if IP in packet:
            print(f'{packet.summary()}')  # Show details of the captured packet
        
    def pkt_sniff():
        # Start sniffing packets
        sniff(prn=packet_callback, filter=f"host {target}")
                    
    sniff_thread = threading.Thread(target=pkt_sniff)
    sniff_thread.daemon = True
    sniff_thread.start()
        
        
  