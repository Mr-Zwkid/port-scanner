import socket
from scapy.all import IP, UDP, ICMP, sr1

class UDPScanner:
    def __init__(self):
        pass

    def udp_scan(self, host, port):
        try:
            # 发送 UDP 包并等待响应
            pkt = IP(dst=host)/UDP(dport=port)
            resp = sr1(pkt, timeout=2, verbose=0)
            
            if resp is None:
                return True  # 可能开放（无响应）
            elif resp.haslayer(ICMP):
                if int(resp[ICMP].type) == 3 and int(resp[ICMP].code) == 3:
                    return False  # 端口关闭
                elif int(resp[ICMP].type) == 3 and int(resp[ICMP].code) in [1, 2, 9, 10, 13]:
                    return False  # 被过滤
            else:
                return True  # 端口开放
                
        except Exception as e:
            print(f"Error during UDP scan: {e}")
            return False
