def validate_ip(ip):
    if not ip:
        return False
    try:
        # 检查IP格式
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        # 检查每个部分是否为0-255的整数
        return all(0 <= int(part) <= 255 for part in parts)
    except (AttributeError, TypeError, ValueError):
        return False

def validate_port(port):
    try:
        port_num = int(port)
        return 0 <= port_num <= 65535
    except ValueError:
        return False

def format_results(results):
    formatted = []
    for host, status in results.items():
        formatted.append(f"{host}: {'Online' if status else 'Offline'}")
    return "\n".join(formatted)