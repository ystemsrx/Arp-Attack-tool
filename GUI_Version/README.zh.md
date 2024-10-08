[English](README.md)

[返回主页](https://github.com/ystemsrx/Arp-Attack-tool)

# ARP 攻击工具 (GUI 版本)

## 概述

本项目是一个基于 Python 的图形用户界面 (GUI) 工具，设计用于网络扫描和执行 ARP 欺骗（中间人攻击）。它使用 PyQt5 框架构建图形用户界面，并使用 Scapy 进行网络数据包操作。

## 功能

- **网络扫描**：该工具可以扫描本地网络以识别设备，显示它们的 IP、MAC 地址和制造商信息。
- **ARP 欺骗**：用户可以从已扫描设备列表中选择目标并启动 ARP 欺骗攻击，通过发送伪造的 ARP 数据包来重定向流量。
- **多语言支持**：界面支持英文和简体中文[（v2.1）](Arp_Attack_GUI_v2.1.py)，用户可以在两种语言之间切换。
- **始终在顶层**：可以选择使窗口始终保持在其他窗口之上。

## 环境要求

- Python 3.x
- PyQt5
- Scapy
- netifaces
- requests

## 使用方法

1. **启动应用程序**：运行脚本启动 GUI。

![image](https://github.com/user-attachments/assets/7e242d67-c1f9-4cfa-a02b-430a3042ffdb)

2. **扫描网络**：点击“扫描网络”按钮开始扫描本地网络。设备的 IP、MAC 地址和制造商信息将显示在列表中。

![image](https://github.com/user-attachments/assets/b589b207-9c7c-4d4e-a54c-163948624dc9)

3. **选择目标**：从列表中选择要攻击的设备。
4. **配置攻击**：指定每秒发送的 ARP 数据包数量。
![image](https://github.com/user-attachments/assets/68bad39d-af59-4414-84a1-0d45c6c39b26)

5. **开始攻击**：点击“开始 ARP 攻击”按钮以启动 ARP 欺骗攻击。
6. **停止攻击**：攻击可以随时通过点击“停止攻击”按钮停止。

![image](https://github.com/user-attachments/assets/149ae65e-6e0b-4b84-a9a4-0490e655f971)

## GUI 组件

- **扫描网络按钮**：启动网络扫描过程。
- **设备列表**：显示已扫描的设备及其相应的 IP 和 MAC 地址。
- **目标索引**：允许手动输入目标设备的索引以进行选择。
- **每秒数据包数量**：配置攻击期间发送 ARP 数据包的速率。
- **语言切换**：在界面上切换英文和简体中文。
- **始终在顶层复选框**：使窗口保持在其他应用程序之上。

## 故障排查

**问题**：如果你遇到以下错误信息：

`Failed to scan network: Sniffing and sending packets is not available at layer2: winpcap is not installed. You may use conf.L3socket or comg.L3socket6 to access layer 3.`

**解决方案**：这个错误是因为你的系统中没有安装 `WinPcap`。要解决这个问题，你需要：

1. **安装 Npcap**：`Npcap` 是 `WinPcap` 的现代替代品，兼容大多数需要 `WinPcap` 的应用程序。你可以从 [Npcap 的官方网站](https://nmap.org/npcap/) 下载并安装 `Npcap`。

这样可以帮助用户在遇到这个错误时知道如何进行故障排查并解决问题。

## 安全声明

**本工具仅供教育用途。** 在没有网络所有者明确许可的情况下，未经授权使用 ARP 欺骗工具进行网络攻击是违法和不道德的。在进行任何网络攻击之前，请确保您已获得必要的许可。

## 许可

本项目采用 MIT 许可。有关详细信息，请参阅 `LICENSE` 文件。

## 贡献

欢迎对本项目做出贡献。请提交包含清晰描述的拉取请求，并确保您的代码符合本项目的编码标准。
