import os
class ICMPScanner:
    def __init__(self):
        pass

    def ping_host(self, host):
        # 使用 ping 命令来判断主机是否在线
        response = os.system(f"ping -n 1 {host}")
        return response == 0