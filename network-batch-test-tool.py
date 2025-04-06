import tkinter as tk
from tkinter import ttk, messagebox
import tkinter.font  
import requests
import re
from threading import Thread
from queue import Queue
from bs4 import BeautifulSoup
import socket
import struct
import time
from reportlab.lib.pagesizes import letter 
from reportlab.pdfgen import canvas 
from reportlab.pdfbase import pdfmetrics 
from reportlab.pdfbase.ttfonts import TTFont
import netifaces 
import os 
import subprocess

# 注册字体
pdfmetrics.registerFont(TTFont('SimSun',  'simsun.ttc'))

class WebsiteChecker:
    def __init__(self, master):
        self.master = master
        master.title("网络访问批量测试工具v1.2")
        master.geometry("1000x840")  
        # 获取本机IP地址、网关IP地址并检测网关是否可达
        self.local_ip  = self.get_local_ip()
        self.gateway_ip  = self.get_gateway() 
        self.gateway_reachable  = self.ping_gateway() 
           # 设置标题字体
        title_font = ("SimSun", 15)
        title_label = tk.Label(master, text="网络访问批量测试工具v1.2", font=title_font)
        title_label.pack(pady=1)  
        
        # 显示本机IP、网关IP和网关可达状态在一行
        ip_info_text = f"本机IP地址: {self.local_ip} | 网关IP地址: {self.gateway_ip  if self.gateway_ip  else '未知'} | 网关可达状态: {'可达' if self.gateway_reachable  else '不可达'}"
        self.ip_info_text = ip_info_text
        #ip_label = tk.Label(master, text=ip_info_text)
        #ip_label.pack(pady=1) 
        self.master.title(f"网络访问批量测试工具:   {ip_info_text}")

        self.create_widgets()  
        self.check_queue   = Queue()
        self.tcp_check_queue   = Queue()
        self.running   = False
        self.tcp_running   = False
        self.completed_threads   = 0
        self.tcp_completed_threads   = 0


    def create_widgets(self):
        # 网站检测输入区域
        website_input_frame = tk.Frame(self.master)  
        website_input_frame.pack(pady=10,   fill=tk.X)
        title_font = ("SimSun", 12)
        tk.Label(website_input_frame, text="待检测Web服务URL列表(以英文,或Tab隔开/可从Excel复制:[URL 业务名称]):", font=title_font).pack(side=tk.TOP, anchor=tk.W)

        # 创建行号显示的Text组件 
        self.url_line_numbers  = tk.Text(website_input_frame, width=3, height=8, borderwidth=0, highlightthickness=0) 
        self.url_line_numbers.pack(side=tk.LEFT,  padx=(5, 0)) 
        
        self.url_input  = tk.Text(website_input_frame, height=8, width=76) 
        self.url_input.pack(side=tk.LEFT,  padx=5) 
 
        # 插入示例数据 \t 表示Tab键隔开, 或者以 ，逗号隔开都可以 
        self.url_input.insert(tk.END,  "https://www.baidu.com\t 百度\n") 
        self.url_input.insert(tk.END,  "https://www.163.com\t 网易\n") 


        # 网站检测输入区域设置为不可编辑
        #self.url_input.config(state=tk.DISABLED)

        # 绑定滚动事件 
        self.url_input.bind("<KeyRelease>",  lambda event: self.update_line_numbers_url(self.url_input,  self.url_line_numbers))  
        self.url_input.bind("<MouseWheel>",  lambda event: self.sync_scroll(self.url_input,  self.url_line_numbers,  event)) 
        self.url_line_numbers.bind("<MouseWheel>",  lambda event: self.sync_scroll(self.url_line_numbers,  self.url_input,  event)) 
       
 
        # 更新行号 
        self.update_line_numbers_url(self.url_input,  self.url_line_numbers)  

        # 网站检测按钮
        style = ttk.Style()
        style.configure("Blue.TButton",    background="blue", foreground="black")
        self.check_btn = ttk.Button(website_input_frame, text="开始检测网站", command=self.start_website_check, style="Blue.TButton")
        self.check_btn.pack(side=tk.LEFT, padx=25)

         # 导出网站检测结果PDF按钮 
        self.export_pdf_btn  = ttk.Button(website_input_frame,  text="导出网站检测结果为 PDF", command=self.export_website_to_pdf,  
        style="Blue.TButton") 
        self.export_pdf_btn.pack(side=tk.LEFT, padx=45)  
 
        # 结果表格（网站检测）
        columns = ("序号", "URL", "业务名称", "HTTP 状态码", "访问结果")
        self.result_tree   = ttk.Treeview(
            self.master,    columns=columns, show="headings", selectmode="browse"
        )

        # 设置列宽
        col_widths = {
            "序号": 50,
            "URL": 250,
            "业务名称": 150,
            "HTTP 状态码": 100,
            "访问结果": 100
        }
        for col, width in col_widths.items():  
            self.result_tree.column(col,    width=width, anchor=tk.CENTER)

        # 设置表头
        for col in columns:
            self.result_tree.heading(col,    text=col)

        # 设置颜色标签
        self.result_tree.tag_configure("success",    background="#dfffdf")
        self.result_tree.tag_configure("fail",    background="#ffdfdf")
        self.result_tree.pack(fill=tk.BOTH,    expand=True, padx=10, pady=5)

        # TCP/UDP 检测输入区域
        tcp_input_frame = tk.Frame(self.master)  
        tcp_input_frame.pack(pady=10,    fill=tk.X)
        title_font = ("SimSun", 12)
        tk.Label(tcp_input_frame, text="待检测TCP/UDP服务列表(以英文,或Tab隔开/可从Excel复制:[IP，协议，端口，业务名称]):", font=title_font).pack(side=tk.TOP, anchor=tk.W)

        # 创建行号显示的Text组件 
        self.tcp_line_numbers  = tk.Text(tcp_input_frame, width=3, height=8, borderwidth=0, highlightthickness=0) 
        self.tcp_line_numbers.pack(side=tk.LEFT,  padx=(5, 0)) 
        self.tcp_data_text  = tk.Text(tcp_input_frame, height=8, width=76) 
        self.tcp_data_text.pack(side=tk.LEFT,  padx=5) 
 
        # 插入示例数据 \t 表示以Tab键隔开，或者以 ，逗号隔开都可以 
        self.tcp_data_text.insert(tk.END, "223.5.5.5,UDP,53,阿里云UDPDNS\n") 
        self.tcp_data_text.insert(tk.END, "223.5.5.5,TCP,53,阿里云TCPDNS\n")
        # tcp/udp检测输入区域设置为不可编辑 
        #self.tcp_data_text.config(state=tk.DISABLED)  

        # 绑定滚动事件 
        self.tcp_data_text.bind("<KeyRelease>",  lambda event: self.update_line_numbers_tcp(self.tcp_data_text,  self.tcp_line_numbers))  
        self.tcp_data_text.bind("<MouseWheel>",  lambda event: self.sync_scroll(self.tcp_data_text,  self.tcp_line_numbers,  event)) 
        self.tcp_line_numbers.bind("<MouseWheel>",  lambda event: self.sync_scroll(self.tcp_line_numbers,  self.tcp_data_text,  event)) 
        self.tcp_data_text.bind("<<Modified>>",  lambda event: self.update_line_numbers_tcp(self.tcp_data_text,  self.tcp_line_numbers)) 
        
        # 更新行号 
        self.update_line_numbers_tcp(self.tcp_data_text,  self.tcp_line_numbers)  
    

        # TCP/UDP 检测按钮
        self.tcp_check_btn   = ttk.Button(tcp_input_frame, text="开始检测 TCP/UDP", command=self.start_tcp_check,  style="Blue.TButton")
        self.tcp_check_btn.pack(side=tk.LEFT, padx=15)

        # 导出TCP/UDP检测结果为PDF按钮 
        self.export_pdf_btn2  = ttk.Button(tcp_input_frame,  text="导出TCP/UDP检测结果为PDF", command=self.export_tcp_udp_to_pdf,  
        style="Blue.TButton") 
        self.export_pdf_btn2.pack(side=tk.LEFT, padx=25)

        # TCP/UDP 检测结果表格
        tcp_columns = ("序号", "IP 地址", "端口", "业务名称", "访问结果")
        self.tcp_result_tree   = ttk.Treeview(
        self.master,  columns=tcp_columns, show="headings", selectmode="browse"
        )

        # 设置列宽
        tcp_col_widths = {
            "序号": 50,
            "IP 地址": 150,
            "端口": 100,
            "业务名称": 150,
            "访问结果": 100
        }
        for col, width in tcp_col_widths.items():  
            self.tcp_result_tree.column(col, width=width, anchor=tk.CENTER)

        # 设置表头
        for col in tcp_columns:
            self.tcp_result_tree.heading(col, text=col)

        # 设置颜色标签
        self.tcp_result_tree.tag_configure("tcp_success",    background="#dfffdf")
        self.tcp_result_tree.tag_configure("tcp_fail",    background="#ffdfdf")
        self.tcp_result_tree.pack(fill=tk.BOTH,    expand=True, padx=10, pady=5)

        # 状态栏
        self.status_var   = tk.StringVar()
        status_bar = ttk.Label(self.master, textvariable=self.status_var,    relief=tk.SUNKEN)
        status_bar.pack(side=tk.BOTTOM,    fill=tk.X)

    def update_line_numbers_url(self, text_widget, line_number_widget): 
        self.url_line_numbers.config(state=tk.NORMAL)
        line_count = int(text_widget.index('end-1c').split('.')[0])  
        line_numbers = '\n'.join(str(i) for i in range(1, line_count + 1)) 
        line_number_widget.delete('1.0',  tk.END) 
        line_number_widget.insert(tk.END,  line_numbers) 
        # 同步滚动位置 
        line_number_widget.yview_moveto(text_widget.yview()[0]) 
        # 重置修改标志 
        text_widget.edit_modified(False)  
        self.url_line_numbers.config(state=tk.DISABLED)

    def update_line_numbers_tcp(self, text_widget, line_number_widget): 
        self.tcp_line_numbers.config(state=tk.NORMAL)
        line_count = int(text_widget.index('end-1c').split('.')[0])  
        line_numbers = '\n'.join(str(i) for i in range(1, line_count + 1)) 
        line_number_widget.delete('1.0',  tk.END) 
        line_number_widget.insert(tk.END,  line_numbers) 
        # 同步滚动位置 
        line_number_widget.yview_moveto(text_widget.yview()[0]) 
        # 重置修改标志 
        text_widget.edit_modified(False)  
        self.tcp_line_numbers.config(state=tk.DISABLED)
 
    def sync_scroll(self, source_widget, target_widget, event): 
        if event.delta:  
            source_widget.yview_scroll(int(-1  * (event.delta  / 120)), "units") 
            target_widget.yview_scroll(int(-1  * (event.delta  / 120)), "units") 
        else: 
            if event.num  == 5: 
                move = 1 
            else: 
                move = -1 
            source_widget.yview_scroll(move,  "units") 
            target_widget.yview_scroll(move,  "units") 
        return "break" 

    def start_website_check(self):
        if self.running:  
            return

        urls = []
        invalid_lines = [] 
        for line_num, line in enumerate(self.url_input.get("1.0",  tk.END).strip().split('\n'), start=1): 
            # \t表示一个Tab分隔，可以直接复制excel表格内容进行粘贴，若要以逗号分割，将 \t 替换为 ,
            #parts = [x.strip() for x in line.split('\t',  1)] 
            parts = [x.strip() for x in re.split(r'[,\t]',  line) if x.strip()]
            if len(parts) < 2: 
                invalid_lines.append(line_num)  
            else: 
               urls.append((parts[0],  parts[1])) 

        if  invalid_lines: 
             error_msg = "以下行的格式不正确，请按格式填写：\n" + ",".join(map(str, invalid_lines)) 
             messagebox.showwarning(" 格式错误", error_msg) 
             return 

        if not urls:
            messagebox.showwarning("提示", "请输入至少一个 URL")
            return

        self.running   = True
        self.completed_threads   = 0
        self.check_btn.config(text="   检测中...", state=tk.DISABLED)
        self.result_tree.delete(*self.result_tree.get_children())  
        self.status_var.set(f"   开始检测 {len(urls)} 个网站...")

        # 启动网站检测线程
        for i, (url, title) in enumerate(urls, 1):
            Thread(target=self.check_website,    args=(i, url, title), daemon=True).start()

        self.master.after(100,    self.process_queue)  

    def start_tcp_check(self):
        if self.tcp_running:  
            return
        tcp_services = [] 
        invalid_lines = [] 
        for line_num, line in enumerate(self.tcp_data_text.get("1.0",  tk.END).strip().split('\n'), start=1): 
            
            #parts = [x.strip() for x in line.split('\t')]   在 Python 中，字符串对象的 split() 方法只能指定一个分隔符, 用re可以指定多个
            parts = [x.strip() for x in re.split(r'[,\t]',  line) if x.strip()]
            if len(parts) < 4: 
                invalid_lines.append(line_num)  
                continue 
            try: 
                tcp_services.append((parts[0],  parts[1], int(parts[2]), parts[3])) 
            except ValueError: 
                invalid_lines.append(line_num)  
    
        if invalid_lines: 
            error_msg = "以下行的格式不正确，请按格式填写：\n" + ",".join(map(str, invalid_lines)) 
            messagebox.showwarning(" 格式错误", error_msg) 
            return 
    
        if not tcp_services: 
            messagebox.showwarning(" 提示", "请输入有效的 TCP/UDP 检测数据") 
            return 
    
        self.tcp_running   = True
        self.tcp_completed_threads   = 0
        self.tcp_check_btn.config(text="检测中...", state=tk.DISABLED)
        self.tcp_result_tree.delete(*self.tcp_result_tree.get_children())  
        self.status_var.set(f"   开始检测 {len(tcp_services)} 个 TCP/UDP 服务...")

        # 启动 TCP/UDP 检测线程
        for i, (ip, protocol, port, service) in enumerate(tcp_services, 1):
            if protocol.upper()   == "TCP":
                Thread(target=self.check_tcp,    args=(i, ip, protocol, port, service), daemon=True).start()
            elif protocol.upper()   == "UDP":
                Thread(target=self.check_udp,    args=(i, ip, protocol, port, service), daemon=True).start()

        self.master.after(100,    self.process_tcp_queue)  

    def check_website(self, index, url, preset_title):
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        }
        status_code = "未知状态"
        actual_title = "无内容"
        result = "访问失败"
        tag = "fail"
        try:
                # 精简后的核心请求配置 
                response = requests.get( 
                    url,
                    headers=headers,
                    timeout=5,
                    allow_redirects=False,
                    verify=False 
                )
                
                # 保留原变量赋值逻辑 
                status_code = response.status_code  
                content_type = response.headers.get('Content-Type',  '')
                
                # 增强型标题解析（保持变量名不变）
                if 'text/html' in content_type:
                    try:
                        actual_title = BeautifulSoup(response.text,  'html.parser').title.string.strip()[:100] 
                    except:
                        actual_title = "HTML解析失败"
                else:
                    actual_title = content_type.split(';')[0]  if content_type else "二进制内容"
        
                # 核心变更点：只要获得响应即为成功 
                result = "访问成功"
                tag = "success"
        
        except requests.exceptions.RequestException  as e:
            # 保持异常类型分类 
            status_code = f"{type(e).__name__}"
            actual_title = str(e)[:100]
        except Exception as e:
            # 兜底异常处理 
            status_code = f"{type(e).__name__}"
            actual_title = str(e)[:100]
        
        # 严格保持原输出队列格式 
        self.check_queue.put((index,  url, preset_title, status_code, result, tag))
                
    def check_tcp(self, index, ip, protocol, port, service_name):
        try:
            sock = socket.socket(socket.AF_INET,    socket.SOCK_STREAM)
            sock.settimeout(5)  
            result = sock.connect_ex((ip,    port))
            if result == 0:
                status = "访问成功"
                tag = "tcp_success"
            else:
                status = "访问失败"
                tag = "tcp_fail"
            sock.close()  
        except Exception as e:
            status = f"错误: {str(e)}"
            tag = "tcp_fail"

        port_str = f"{protocol.upper()}/{port}"  
        self.tcp_check_queue.put((index,    ip, port_str, service_name, status, tag))

    def check_udp(self, index, ip, protocol, port, service_name):
            try:
                sock = socket.socket(socket.AF_INET,  socket.SOCK_DGRAM)
                sock.settimeout(5) 
                
                # 协议特异性检测逻辑
                if port == 123:  # NTP检测
                    # 构造NTP请求报文（Mode 3: Client）
                    ntp_packet = bytearray(48)
                    ntp_packet[0] = 0x1B  # LI=0, Version=3, Mode=3
                    sock.sendto(ntp_packet,  (ip, port))
                    data, _ = sock.recvfrom(1024) 
                    # 验证NTP响应有效性
                    if len(data) >= 48 and data[0] & 0x07 == 0x04:  # Mode 4: Server
                        status = "访问成功"
                        tag = "tcp_success"
                    else:
                        status = "响应异常"
                        tag = "tcp_fail"

                elif port == 514:  # SYSLOG检测
                    # 发送测试日志消息（RFC5424格式）
                    message = f"<14>1 {time.strftime('%Y-%m-%dT%H:%M:%SZ')}  localhost - - - Test message"
                    sock.sendto(message.encode(),  (ip, port))
                    # UDP无连接协议不等待响应
                    status = "端口可达"
                    tag = "tcp_success"

                elif port == 53:  # DNS检测
                    # 构造DNS查询请求（查询www.example.com 的A记录）
                    dns_packet = bytearray()
                    dns_packet.extend(struct.pack('!H',  0x1234))  # 事务ID
                    dns_packet.extend(struct.pack('!H',  0x0100))  # 标志
                    dns_packet.extend(struct.pack('!H',  1))  # 问题数量
                    dns_packet.extend(struct.pack('!H',  0))  # 回答资源记录数量
                    dns_packet.extend(struct.pack('!H',  0))  # 权威名称服务器数量
                    dns_packet.extend(struct.pack('!H',  0))  # 额外资源记录数量

                    domain = "www.example.com" 
                    for part in domain.split('.'): 
                        dns_packet.append(len(part)) 
                        dns_packet.extend(part.encode()) 
                    dns_packet.append(0)   # 域名结束标志
                    dns_packet.extend(struct.pack('!H',  1))  # 查询类型（A记录）
                    dns_packet.extend(struct.pack('!H',  1))  # 查询类（IN）

                    sock.sendto(dns_packet,  (ip, port))
                    try:
                        data, _ = sock.recvfrom(1024) 
                        status = "访问成功"
                        tag = "tcp_success"
                    except socket.timeout: 
                        status = "访问失败"
                        tag = "tcp_fail"

                elif port == 1812 or port == 1813:  # Radius检测
                    # 简单的Radius请求，实际应用中需要更复杂的认证逻辑
                    radius_packet = bytearray()
                    radius_packet.extend(struct.pack('!B',  1))  # 代码：Access-Request
                    radius_packet.extend(struct.pack('!B',  1))  # 标识符
                    radius_packet.extend(struct.pack('!H',  20))  # 长度
                    radius_packet.extend(b'\x00'  * 16)  # 认证器
                    sock.sendto(radius_packet,  (ip, port))
                    try:
                        data, _ = sock.recvfrom(1024) 
                        status = "访问成功"
                        tag = "tcp_success"
                    except socket.timeout: 
                        status = "访问失败"
                        tag = "tcp_fail"

                elif port == 25:  # SMTP 25端口检测
                    # 发送简单的SMTP EHLO命令
                    command = b'EHLO example.com\r\n' 
                    sock.sendto(command,  (ip, port))
                    try:
                        data, _ = sock.recvfrom(1024) 
                        status = "访问成功"
                        tag = "tcp_success"
                    except socket.timeout: 
                        status = "访问失败"
                        tag = "tcp_fail"

                elif port == 389:  # LDAP 389端口检测
                    # 发送简单的LDAP绑定请求
                    ldap_packet = bytearray()
                    ldap_packet.extend(struct.pack('!B',  0x30))  # LDAP消息头
                    ldap_packet.extend(struct.pack('!B',  13))  # 消息长度
                    ldap_packet.extend(struct.pack('!B',  0x02))  # 消息ID
                    ldap_packet.extend(struct.pack('!B',  1))
                    ldap_packet.extend(struct.pack('!B',  0x01))
                    ldap_packet.extend(struct.pack('!B',  0x60))  # 绑定请求
                    ldap_packet.extend(struct.pack('!B',  8))
                    ldap_packet.extend(struct.pack('!B',  0x02))  # 版本
                    ldap_packet.extend(struct.pack('!B',  1))
                    ldap_packet.extend(struct.pack('!B',  0x03))
                    ldap_packet.extend(struct.pack('!B',  0x04))  # 绑定DN
                    ldap_packet.extend(struct.pack('!B',  0))
                    ldap_packet.extend(struct.pack('!B',  0x80))  # 认证方式
                    ldap_packet.extend(struct.pack('!B',  0))
                    sock.sendto(ldap_packet,  (ip, port))
                    try:
                        data, _ = sock.recvfrom(1024) 
                        status = "访问成功"
                        tag = "tcp_success"
                    except socket.timeout: 
                        status = "访问失败"
                        tag = "tcp_fail"

                else:  # 通用UDP检测
                    # 发送空数据包检测端口可达性
                    sock.sendto(b'',  (ip, port))
                    try:
                        data, _ = sock.recvfrom(1024) 
                        status = "访问成功"
                        tag = "tcp_success"
                    except socket.timeout: 
                        status = "端口可达"  # UDP协议特性
                        tag = "tcp_success"

            except Exception as e:
                status = f"错误: {str(e)}"
                tag = "tcp_fail"
            finally:
                sock.close() 
    
            port_str = f"{protocol.upper()}/{port}" 
            self.tcp_check_queue.put((index,  ip, port_str, service_name, status, tag))

    def export_website_to_pdf(self):
        """将检测结果导出为PDF文件"""
        if not any([self.result_tree.get_children(), self.tcp_result_tree.get_children()]): 
            messagebox.showwarning(" 提示", "没有检测结果可以导出")
            return 
 
        from datetime import datetime 
        import os 
        
        # 创建PDF文件 
        filename = f"网络检测报告_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf" 
        c = canvas.Canvas(filename, pagesize=letter)
        
        # 设置标题样式 
        c.setFont("SimSun",  16)
        c.drawString(50,  750, "网络技术部业务检测报告")
        
        # 设置日期 
        c.setFont("SimSun",  10)
        c.drawString(450,  750, f"生成时间: {datetime.now().strftime('%Y-%m-%d  %H:%M:%S')}")

        # 添加IP信息 
        c.setFont("SimSun",   10) 
        c.drawString(50,730, self.ip_info_text) 
        
        # 绘制网站检测结果 
        self._draw_website_results(c)
        
        # 保存PDF 
        c.save() 
        
        # 打开PDF文件 
        try:
            os.startfile(filename) 
        except:
            messagebox.showinfo(" 提示", f"报告已生成: {os.path.abspath(filename)}") 
 
    def export_tcp_udp_to_pdf(self):
        """将检测结果导出为PDF文件"""
        if not any([self.result_tree.get_children(), self.tcp_result_tree.get_children()]): 
            messagebox.showwarning(" 提示", "没有检测结果可以导出")
            return 
 
        from datetime import datetime 
        import os 
        
        # 创建PDF文件 
        filename = f"网络检测报告_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf" 
        c = canvas.Canvas(filename, pagesize=letter)
        
        # 设置标题样式 
        c.setFont("SimSun",  16)
        c.drawString(50,  750, "网络技术部业务检测报告")
        
        # 设置日期 
        c.setFont("SimSun",  10)
        c.drawString(450,  750, f"生成时间: {datetime.now().strftime('%Y-%m-%d  %H:%M:%S')}")

                # 添加IP信息 
        c.setFont("SimSun",   10) 
        c.drawString(50, 730, self.ip_info_text) 
        
        # 绘制TCP/UDP检测结果 
        self._draw_tcp_results(c)
        
        # 保存PDF 
        c.save() 
        
        # 打开PDF文件 
        try:
            os.startfile(filename) 
        except:
            messagebox.showinfo(" 提示", f"报告已生成: {os.path.abspath(filename)}") 

    def _draw_website_results(self, canvas):
        """绘制网站检测结果到PDF"""
        if self.result_tree.get_children(): 
            canvas.setFont("SimSun",  12)
            canvas.drawString(50,  710, "网站检测结果:")
            canvas.setFont("SimSun",  10)
            y_position = 690 
            
            # 表头 
            canvas.drawString(50,  y_position, "序号")
            canvas.drawString(80,  y_position, "URL")
            canvas.drawString(330,  y_position, "业务名称")
            canvas.drawString(430,  y_position, "状态码")
            canvas.drawString(480,  y_position, "访问结果")
            y_position -= 20 
            
            # 绘制表格线 
            canvas.line(50,  y_position+15, 550, y_position+15)
            
            # 数据行 
            for child in self.result_tree.get_children(): 
                item = self.result_tree.item(child)['values'] 
                y_position -= 20 
                
                # 检查是否需要换页 
                if y_position < 50:
                    canvas.showPage() 
                    y_position = 750 
                    canvas.setFont("SimSun",  10)
                    
                canvas.drawString(50,  y_position, str(item[0]))
                canvas.drawString(80,  y_position, str(item[1]))
                canvas.drawString(330,  y_position, str(item[2]))
                canvas.drawString(430,  y_position, str(item[3]))
                canvas.drawString(480,  y_position, str(item[4]))
                
                # 设置成功/失败颜色 
                if "成功" in str(item[4]):
                    canvas.setFillColorRGB(0,  0.5, 0)
                else:
                    canvas.setFillColorRGB(0.8,  0, 0)
                    
                canvas.drawString(480,  y_position, str(item[4]))
                canvas.setFillColorRGB(0,  0, 0)  # 恢复黑色 
            
            y_position -= 30 
 
    def _draw_tcp_results(self, canvas):
        """绘制TCP/UDP检测结果到PDF"""
        if self.tcp_result_tree.get_children():  
            canvas.setFont("SimSun",  12)
            canvas.drawString(50,  710, "TCP/UDP检测结果:")
            canvas.setFont("SimSun",  10)
            y_position = 690
            
            # 表头 
            canvas.drawString(50,  y_position, "序号")
            canvas.drawString(80,  y_position, "IP地址")
            canvas.drawString(180,  y_position, "端口")
            canvas.drawString(230,  y_position, "业务名称")
            canvas.drawString(330,  y_position, "访问结果")
            y_position -= 20 
            
            # 绘制表格线 
            canvas.line(50,  y_position+15, 550, y_position+15)
            
            # 数据行 
            for child in self.tcp_result_tree.get_children(): 
                item = self.tcp_result_tree.item(child)['values'] 
                y_position -= 20 
                
                # 检查是否需要换页 
                if y_position < 50:
                    canvas.showPage() 
                    y_position = 750 
                    canvas.setFont("SimSun",  10)
                    
                canvas.drawString(50,  y_position, str(item[0]))
                canvas.drawString(80,  y_position, str(item[1]))
                canvas.drawString(180,  y_position, str(item[2]))
                canvas.drawString(230,  y_position, str(item[3]))
                
                # 设置成功/失败颜色 
                if "成功" in str(item[4]):
                    canvas.setFillColorRGB(0,  0.5, 0)
                else:
                    canvas.setFillColorRGB(0.8,  0, 0)
                    
                canvas.drawString(330,  y_position, str(item[4]))
                canvas.setFillColorRGB(0,  0, 0)  # 恢复黑色 
            
            y_position -= 30 
 
    def process_queue(self):
        """处理网站检测队列"""
        while not self.check_queue.empty(): 
            index, url, title, status_code, result, tag = self.check_queue.get() 
            self.result_tree.insert("",  tk.END, values=(index, url, title, status_code, result), tags=(tag,))
            self.completed_threads  += 1 
            self.status_var.set(f"已完成 {self.completed_threads}  个网站检测")
 
        if self.completed_threads  < len(self.url_input.get("1.0",  tk.END).strip().split('\n')):
            self.master.after(100,  self.process_queue) 
        else:
            self.running  = False 
            self.check_btn.config(text=" 开始检测网站", state=tk.NORMAL)
            self.status_var.set("    网站检测完成")
            # 对网站检测结果按序号排序 
            self.sort_treeview(self.result_tree,  "序号", False) 
 
    def process_tcp_queue(self):
        """处理TCP/UDP检测队列"""
        while not self.tcp_check_queue.empty(): 
            index, ip, port, service, result, tag = self.tcp_check_queue.get() 
            self.tcp_result_tree.insert("",  tk.END, values=(index, ip, port, service, result), tags=(tag,))
            self.tcp_completed_threads  += 1 
            self.status_var.set(f"已完成 {self.tcp_completed_threads} 个TCP/UDP检测")
 
        if self.tcp_completed_threads  < len(self.tcp_data_text.get("1.0",  tk.END).strip().split('\n')):
            self.master.after(100,  self.process_tcp_queue) 
        else:
            self.tcp_running  = False 
            self.tcp_check_btn.config(text=" 开始检测 TCP/UDP", state=tk.NORMAL)
            self.status_var.set("    TCP/UDP检测完成")
            # 对TCP/UDP检测结果按序号排序 
            self.sort_treeview(self.tcp_result_tree,  "序号", False) 
    def sort_treeview(self, tree, col, reverse): 
        """对Treeview按指定列排序""" 
        data = [(int(tree.set(child,  col)), child) for child in tree.get_children('')]  
        data.sort(reverse=reverse)  
        for index, (_, child) in enumerate(data): 
            tree.move(child,  '', index) 

    def get_local_ip(self):
        """获取本机IP地址"""
        try:
            # 获取默认网关接口 
            gws = netifaces.gateways() 
            default_gateway = gws['default'][netifaces.AF_INET]
            interface = default_gateway[1]
            
            # 获取该接口的IP地址 
            addrs = netifaces.ifaddresses(interface) 
            ip_info = addrs[netifaces.AF_INET][0]
            return ip_info['addr']
        except Exception as e:
            print(f"获取本地IP失败: {e}")
            return "127.0.0.1"
 
    def get_gateway(self):
        """获取网关IP地址""" 
        try:
            gws = netifaces.gateways() 
            return gws['default'][netifaces.AF_INET][0]
        except Exception as e:
            print(f"获取网关IP失败: {e}")
            return None 
    
    def ping_gateway(self):
        """检测网关是否可达"""
        if not self.gateway_ip: 
            return False 
            
        try:
            # Windows系统使用'-n'参数，Linux/Mac使用'-c'参数 
            param = '-n' if os.name  == 'nt' else '-c'
            count = '1'
            timeout = '1000'  # 毫秒 
            
            # 构建ping命令 
            command = ['ping', param, count, '-w', timeout, self.gateway_ip] 
            
            # 执行ping命令，不显示输出窗口 
            result = subprocess.run(command,  
                                stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE,
                                creationflags=subprocess.CREATE_NO_WINDOW if os.name  == 'nt' else 0)
            
            return result.returncode  == 0 
        except Exception as e:
            print(f"ping网关失败: {e}")
            return False 

    
if __name__ == "__main__":
    root = tk.Tk()
    app = WebsiteChecker(root)
    root.mainloop()  
