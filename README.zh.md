[English](README.md)

[小白请点这里](docs/README_GUI.zh.md)

# ARP 断网工具

还在为蹭网而苦恼吗？还在为亲戚家孩子上门打游戏吵闹而烦躁吗？来试试这个ARP攻击脚本吧！这个脚本是一款简单有效的工具，专为帮助您了解网络协议的漏洞而设计。无论是想开个无伤大雅的小玩笑，还是想深入了解网络安全的重要性，这个脚本都是您学习和实践的绝佳伙伴（仅供教育用途！）。

同时还有一个基于PyQt5的具有图形用户界面易于操作的版本可供选择（需安装PyQt5库）[点击此处](GUI_Version)

## 目录

- [概述](#概述)
- [功能](#功能)
- [环境要求](#环境要求)
- [安装](#安装)
- [使用方法](#使用方法)
- [免责声明](#免责声明)
- [许可证](#许可证)

## 概述

ARP断网工具是一个用于在网络上执行ARP（地址解析协议）欺骗攻击的程序。它旨在演示网络攻击如何发生，并强调实施有效安全措施的必要性。通过这个脚本，您可以临时中断设备的网络连接，非常适合用来对付蹭网的邻居或者捉弄那些打游戏吵闹的亲戚小孩。

## 功能

- **网络扫描：** 自动扫描并列出网络上的设备，显示其IP和MAC地址以及对应设备制造商。
- **制造商检测：** 尝试识别每个网络设备的制造商。
- **ARP欺骗：** 向选定设备发送伪造的ARP包，以中断它们的网络连接。
- **多线程：** 使用线程同时针对多个设备进行操作。

## 环境要求

要运行此脚本，您需要：

- Python 3.x
- 以下Python包：
  - `scapy`
  - `netifaces`
  - `requests`
  - `python-nmap`
  - `PyQt5`（可选）

- nmap安装
  - 前往[nmap下载](https://nmap.org/download.html)选择适用于你电脑的版本进行下载。

对于Linux用户，请确保您拥有root权限来执行此脚本。

## 安装

1. **克隆仓库：**
   ```bash
   git clone https://github.com/ystemsrx/arp-attack-script.git
   cd arp-attack-script
   ```

2. **安装所需软件包：**
   ```bash
   pip install -r requirements.txt
   ```
   如果想要运行带有图形界面的`Arp_Attack_GUI.py`，在终端运行`pip install PyQt5`

## 使用方法

1. **运行脚本：**
   ```bash
   sudo python Arp_Attack.py
   ```
   或
   ```bash
   sudo python Arp_Attack_GUI.py
   ```

3. **按照提示操作：**
   - 脚本将扫描您的网络并显示在线设备列表。
   - 输入您要攻击的设备索引（例如：`0 2 4`）。
   - 指定您希望每秒发送的数据包数量。

4. **观察效果：**
   - 脚本将开始向目标设备发送ARP数据包，并会中断它们的网络连接。

以下是中英文的 README 文件更新内容，你可以根据需要直接复制粘贴到你的 README 中。

## 故障排查

**问题**：如果你遇到以下错误信息：

`Failed to scan network: Sniffing and sending packets is not available at layer2: winpcap is not installed. You may use conf.L3socket or comg.L3socket6 to access layer 3.`

**解决方案**：这个错误是因为你的系统中没有安装 `WinPcap`。要解决这个问题，你需要：

1. **安装 Npcap**：`Npcap` 是 `WinPcap` 的现代替代品，兼容大多数需要 `WinPcap` 的应用程序。你可以从 [Npcap 的官方网站](https://nmap.org/npcap/) 下载并安装 `Npcap`。

这样可以帮助用户在遇到这个错误时知道如何进行故障排查并解决问题。

## 免责声明

此脚本仅用于教育目的。它旨在展示网络协议的漏洞并强调网络安全的重要性。请负责任地使用它，并仅在您拥有明确许可的网络上使用。未经授权在不属于您的网络上或未获得许可的情况下使用此脚本是非法且不道德的行为。

愿您在学习中获得乐趣，记得将知识用在正道上哦！

## 许可证

本项目根据 MIT 许可证授权 - 详情请见 [LICENSE](LICENSE) 文件。
