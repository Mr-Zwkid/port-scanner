import socket
from scapy.all import IP, TCP, sr1

class TCPScanner:
    def __init__(self, target=None):
        self.target = target

    def tcp_connect_scan(self, host, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception as e:
            print(f"Error: {e}")
            return False

    def tcp_syn_scan(self, host, port):
        try:
            pkt = IP(dst=host)/TCP(dport=port, flags="S")
            resp = sr1(pkt, timeout=1, verbose=0)
            if resp is None:
                return False
            if resp.haslayer(TCP):
                # 检查TCP响应中的SYN/ACK标志
                if resp.getlayer(TCP).flags == 0x12:
                    return True
                # 检查TCP响应中的RST标志
                elif resp.getlayer(TCP).flags == 0x14:
                    return False
            return False
        except Exception as e:
            print(f"Error: {e}")
            return False

    def tcp_fin_scan(self, host, port):
        try:
            pkt = IP(dst=host)/TCP(dport=port, flags="F")
            resp = sr1(pkt, timeout=1, verbose=0)
            if resp is None:
                return False
            if resp.haslayer(TCP):
                # 检查TCP响应中的ACK标志
                if resp.getlayer(TCP).flags == 0x10: 
                    return True
                # 检查TCP响应中的RST标志
                elif resp.getlayer(TCP).flags == 0x14:
                    return False
            return False
        except Exception as e:
            print(f"Error: {e}")
            return False

    def scan_ports(self, ports, scan_type):
        results = {}
        for port in ports:
            if scan_type == 'connect':
                results[port] = self.tcp_connect_scan(self.target, port)
            elif scan_type == 'syn':
                results[port] = self.tcp_syn_scan(self.target, port)
            elif scan_type == 'fin':
                results[port] = self.tcp_fin_scan(self.target, port)
        return results