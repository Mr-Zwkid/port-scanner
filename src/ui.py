import tkinter as tk
from tkinter import messagebox, scrolledtext
from PIL import Image, ImageTk
from icmp_scan import ICMPScanner
from tcp_scan import TCPScanner
from udp_scan import UDPScanner
from datetime import datetime
from utils import validate_ip, validate_port
import os
from tkinter import filedialog

class PortScannerUI:
    def __init__(self, root):
        self.root = root
        self.root.title("My Port Scanner")
        
        # 配置窗口最小尺寸
        self.root.minsize(800, 600)
        
        # 配置主窗口网格权重
        self.root.grid_rowconfigure(2, weight=1)
        self.root.grid_columnconfigure(0, weight=3)
        self.root.grid_columnconfigure(1, weight=1)
        
        # 设置背景图片
        try:
            self.original_bg = Image.open("./assets/background.jpg")
            self.bg_photo = None
            self.update_background()
            self.bg_label = tk.Label(root)
            self.bg_label.place(x=0, y=0, relwidth=1, relheight=1)
            
            # 绑定窗口大小改变事件
            self.root.bind('<Configure>', self.on_resize)
        except:
            self.root.configure(bg='#f0f0f0')
        
        # IP 和 Port 输入框
        input_frame = tk.Frame(root, bg='#a5aeb7', relief='groove', bd=4, cursor='plus')
        input_frame.grid(row=0, column=0, padx=10, pady=10, sticky='nsew')
        
        # 配置input_frame的网格权重
        input_frame.grid_columnconfigure(1, weight=1)

        self.host_label = tk.Label(input_frame, text="Host (IPv4) :", bg='#a5aeb7', font=('Arial', 13, 'bold'))
        self.host_label.grid(row=0, column=0, padx=5, pady=5)
        self.host_entry = tk.Entry(input_frame, width=30)
        self.host_entry.grid(row=0, column=1, padx=5, pady=5)

        self.port_label = tk.Label(input_frame, text="Port:", bg='#a5aeb7', font=('Arial', 13, 'bold'))
        self.port_label.grid(row=1, column=0, padx=5, pady=5)
        self.port_entry = tk.Entry(input_frame, width=30)
        self.port_entry.grid(row=1, column=1, padx=5, pady=5)

        # 扫描方式按钮框
        button_frame = tk.Frame(root)
        button_frame.grid(row=1, column=0, padx=10, pady=10)

        # 美化按钮样式
        button_style = {
            'bg': '#4a90e2',
            'fg': 'white',
            'relief': 'raised',
            'font': ('Arial', 10, 'bold'),
            'width': 15,
            'pady': 5
        }

        self.icmp_button = tk.Button(button_frame, text="ICMP Scan", 
                                   command=self.icmp_scan, **button_style)
        self.icmp_button.grid(row=0, column=0, padx=5, pady=5)

        self.tcp_connect_button = tk.Button(button_frame, text="TCP Connect Scan", command=self.tcp_connect_scan, **button_style)
        self.tcp_connect_button.grid(row=0, column=1, padx=5, pady=5)

        self.tcp_syn_button = tk.Button(button_frame, text="TCP SYN Scan", command=self.tcp_syn_scan, **button_style)
        self.tcp_syn_button.grid(row=1, column=0, padx=5, pady=5)

        self.tcp_fin_button = tk.Button(button_frame, text="TCP FIN Scan", command=self.tcp_fin_scan, **button_style)
        self.tcp_fin_button.grid(row=1, column=1, padx=5, pady=5)

        self.udp_scan_button = tk.Button(button_frame, text="UDP Scan", command=self.udp_scan, **button_style)
        self.udp_scan_button.grid(row=2, column=0, padx=5, pady=5)

        # 清除结果按钮
        self.clear_button = tk.Button(button_frame, text="Clear Results", 
                                    command=self.clear_results,
                                    bg='#ff4444',
                                    fg='white',
                                    relief='raised',
                                    font=('Arial', 10, 'bold'),
                                    width=15,
                                    pady=5)
        self.clear_button.grid(row=2, column=1, padx=5, pady=5)

        # 结果显示区域
        result_frame = tk.Frame(root)
        result_frame.grid(row=2, column=0, padx=10, pady=10, sticky='nsew')
        result_frame.grid_columnconfigure(0, weight=1)
        result_frame.grid_rowconfigure(0, weight=1)

        self.result_text = scrolledtext.ScrolledText(
            result_frame, 
            wrap=tk.WORD,
            font=('Consolas', 10),
            bg='#f8f9fa'
        )
        self.result_text.grid(row=0, column=0, sticky='nsew')

        # 在初始化方法中添加文本标签配置
        self.result_text.tag_configure('timestamp', foreground='#95a5a6')  # 灰色
        self.result_text.tag_configure('success', foreground='#2ecc71')  # 绿色
        self.result_text.tag_configure('error', foreground='#e74c3c')    # 红色
        self.result_text.tag_configure('warning', foreground='#f1c40f')  # 黄色

        # 端口信息框
        port_info_frame = tk.Frame(root)
        port_info_frame.grid(row=0, column=1, rowspan=3, padx=10, pady=10, sticky='nsew')
        port_info_frame.grid_columnconfigure(0, weight=1)
        port_info_frame.grid_rowconfigure(1, weight=1)

        # Save log button
        save_button = tk.Button(
            port_info_frame,
            text="Save Log",
            command=self.save_log,
            bg='#27ae60',
            fg='white',
            font=('Arial', 10, 'bold'),
            width=15,
            pady=5
        )
        save_button.pack(side=tk.BOTTOM, pady=10)

        port_info_label = tk.Label(port_info_frame, text="Frequently Used Ports", font=('Arial', 13, 'bold'))
        port_info_label.pack()

        # 端口信息区域样式
        self.port_info_text = tk.Text(
            port_info_frame,
            height=20,
            width=40,
            font=('Consolas', 11),
            bg='#f8f9fa',
            relief='sunken'
        )
        self.port_info_text.pack(padx=5, pady=5)
        
        # 添加常用端口信息
        common_ports = """
        TCP:
            20,21 - FTP
            22 - SSH
            23 - Telnet
            25 - SMTP
            53 - DNS
            80 - HTTP
            443 - HTTPS
            3306 - MySQL
            3389 - RDP

        UDP:
            53 - DNS
            67,68 - DHCP
            69 - TFTP
            123 - NTP
            161 - SNMP
        """
        self.port_info_text.insert(tk.END, common_ports)
        self.port_info_text.config(state='disabled')

        self.icmp_scanner = ICMPScanner()
        self.tcp_scanner = TCPScanner()
        self.udp_scanner = UDPScanner()

    def insert_colored_result(self, text, status):
        """插入带颜色的扫描结果，添加时间戳"""
        timestamp = datetime.now().strftime('[%Y-%m-%d %H:%M:%S] ')
        full_text = timestamp + text
        self.result_text.insert(tk.END, full_text)
        last_line_start = self.result_text.get("end-2c linestart", "end-1c")
        
        # 给时间戳添加灰色
        self.result_text.tag_add('timestamp', f"end-{len(full_text)+1}c", f"end-{len(text)+1}c")
        
        # 给结果添加相应颜色
        if status == 'Open' or status == 'Online' or status == 'Open/Filtered':
            self.result_text.tag_add('success', f"end-{len(text)+1}c", "end-1c")
        elif status == 'Closed' or status == 'Offline':
            self.result_text.tag_add('error', f"end-{len(text)+1}c", "end-1c")
        self.result_text.see(tk.END)

    def show_error(self, error_msg):
        """显示带时间戳的错误信息"""
        timestamp = datetime.now().strftime('[%Y-%m-%d %H:%M:%S] ')
        full_text = timestamp + f"Error: {error_msg}\n"
        self.result_text.insert(tk.END, full_text)
        
        len_error =  len(f'Error: {error_msg}\\n')
        # 给时间戳添加灰色
        self.result_text.tag_add('timestamp', f"end-{len(full_text)+1}c", f"end-{len_error +1}c")
        # 给错误信息添加黄色
        self.result_text.tag_add('warning', f"end-{len_error+1}c", "end-1c")
        self.result_text.see(tk.END)

    def icmp_scan(self):
        try:
            host = self.host_entry.get()
            if not validate_ip(host):
                self.show_error("Invalid IP address format")
                return
            result = self.icmp_scanner.ping_host(host)
            status = 'Online' if result else 'Offline'
            self.insert_colored_result(f"ICMP Scan result for {host}: {status}\n", status)
        except Exception as e:
            self.show_error(str(e))

    def tcp_connect_scan(self):
        try:
            host = self.host_entry.get()
            port = self.port_entry.get()
            
            if not validate_ip(host):
                self.show_error("Invalid IP address format")
                return
            if not validate_port(port):
                self.show_error("Invalid port number (must be between 0-65535)")
                return

            result = self.tcp_scanner.tcp_connect_scan(host, int(port))
            status = 'Open' if result else 'Closed'
            self.insert_colored_result(f"TCP Connect Scan result for {host} on port {port}: {status}\n", status)
        except Exception as e:
            self.show_error(str(e))

    def tcp_syn_scan(self):
        try:
            host = self.host_entry.get()
            port = self.port_entry.get()
            
            if not validate_ip(host):
                self.show_error("Invalid IP address format")
                return
            if not validate_port(port):
                self.show_error("Invalid port number (must be between 0-65535)")
                return

            result = self.tcp_scanner.tcp_syn_scan(host, int(port))
            status = 'Open' if result else 'Closed'
            self.insert_colored_result(f"TCP SYN Scan result for {host} on port {port}: {status}\n", status)
        except Exception as e:
            self.show_error(str(e))

    def tcp_fin_scan(self):
        try:
            host = self.host_entry.get()
            port = self.port_entry.get()
            
            if not validate_ip(host):
                self.show_error("Invalid IP address format")
                return
            if not validate_port(port):
                self.show_error("Invalid port number (must be between 0-65535)")
                return

            result = self.tcp_scanner.tcp_fin_scan(host, int(port))
            status = 'Open' if result else 'Closed'
            self.insert_colored_result(f"TCP FIN Scan result for {host} on port {port}: {status}\n", status)
        except Exception as e:
            self.show_error(str(e))

    def udp_scan(self):
        try:
            host = self.host_entry.get()
            port = self.port_entry.get()
            
            if not validate_ip(host):
                self.show_error("Invalid IP address format")
                return
            if not validate_port(port):
                self.show_error("Invalid port number (must be between 0-65535)")
                return

            result = self.udp_scanner.udp_scan(host, int(port))
            status = 'Open/Filtered' if result else 'Closed'
            self.insert_colored_result(f"UDP Scan result for {host} on port {port}: {status}\n", status)
        except Exception as e:
            self.show_error(str(e))

    def clear_results(self):
        """清除结果显示区域的内容"""
        self.result_text.delete(1.0, tk.END)

    def save_log(self):
        """保存日志到文件"""
        # 创建output目录(如果不存在)
        if not os.path.exists('./output'):
            os.makedirs('./output')
        
        # 生成文件名 (使用时间戳)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        default_filename = f"scan_log_{timestamp}.txt"
        
        # 获取完整的日志内容
        log_content = self.result_text.get(1.0, tk.END)
        
        # 如果日志为空，显示提示
        if not log_content.strip():
            messagebox.showwarning("Warning", "No log content to save!")
            return
            
        try:
            # 保存文件
            filepath = os.path.join('./output', default_filename)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(log_content)
            messagebox.showinfo("Success", f"Log saved successfully to:\n{filepath}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save log: {str(e)}")

    def update_background(self):
        """更新背景图片大小"""
        if hasattr(self, 'original_bg'):
            width = self.root.winfo_width()
            height = self.root.winfo_height()
            resized = self.original_bg.resize((width, height), Image.Resampling.LANCZOS)
            self.bg_photo = ImageTk.PhotoImage(resized)
            if hasattr(self, 'bg_label'):
                self.bg_label.configure(image=self.bg_photo)

    def on_resize(self, event):
        """窗口大小改变事件处理"""
        if event.widget == self.root:
            self.update_background()
