# Port Scanner

一个使用Python实现的功能完整的端口扫描器，提供图形界面和多种扫描方式。

## 功能特点

- **多种扫描方式**
  - ICMP 扫描：检测主机存活状态
  - TCP Connect 扫描：完整的 TCP 连接测试
  - TCP SYN 扫描：半开放扫描
  - TCP FIN 扫描：使用 FIN 标志的隐蔽扫描
  - UDP 扫描：检测 UDP 端口状态

- **用户友好界面**
  - 直观的图形化操作界面
  - 实时显示扫描结果
  - 内置常用端口信息提示
  - 扫描结果日志保存功能

- **安全特性**
  - IP地址格式验证
  - 端口范围检查
  - 错误处理和提示

## 环境要求

- Python 3.8+
- Windows/Linux 操作系统
- 管理员/Root权限（对于某些扫描类型）

## 文件结构

```
port-scanner
├── assets                 # 项目涉及的展示图片
├── output                 # 项目输出日志
├── src                    # 项目源代码
│   ├── icmp_scan.py       # ICMP扫描功能实现
│   ├── tcp_scan.py        # TCP端口扫描功能实现
│   ├── udp_scan.py        # UDP端口扫描功能实现
│   ├── ui.py              # 用户界面实现
│   └── utils.py           # 实用工具函数
├── main.py                # 项目主函数/入口
├── project_report.pdf     # 项目报告
├── requirements.txt       # 项目依赖库
├── README.txt             # 项目简短说明
└── README.md              # 项目文档
```

## 安装步骤

1. 克隆项目到本地：
   ```
   git clone git@github.com:Mr-Zwkid/port-scanner.git
   ```
2. 进入项目目录：
   ```
   cd port-scanner
   ```
3. 安装依赖：
   ```
   pip install -r requirements.txt
   ```

## 使用方法

1. 在项目文件夹下运行主函数：
   ```
   python main.py
   ```
2. 在界面中输入目标IP地址或主机名，选择扫描类型，然后点击相应扫描按钮进行扫描。
3. 通过 `Save Log` 按钮当前保存日志
4. 通过 `Clear Results` 按钮清除结果框内容

## 贡献

欢迎任何形式的贡献！请提交问题或拉取请求。
