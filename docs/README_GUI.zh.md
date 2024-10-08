[English](README_GUI.en.md)

# ARP 攻击断网工具

## 介绍

此工具旨在通过演示 ARP 欺骗攻击来帮助您理解网络安全。它提供了一个易于使用的图形界面，用于扫描和攻击本地网络上的设备，非常适合用于教育目的和了解网络漏洞。

## 下载

要开始使用，请从[发布页面](https://github.com/ystemsrx/Arp-Attack-tool/releases)下载最新版本的 ARP 攻击 GUI 工具。找到 `.exe` 文件并在您的 Windows 机器上直接运行。

**重要提示：** 此工具需要您的系统上安装 Nmap[(v1.0)](https://github.com/ystemsrx/Arp-Attack-tool/releases/tag/1.0)。请访问 [Nmap 官方下载页面](https://nmap.org/download.html) 并选择适合您操作系统的版本进行下载。对于使用2.0及以上版本的用户无需下载安装此工具

## 使用方法

1. **运行应用程序：** 双击下载的 `.exe` 文件以启动 ARP 攻击 GUI 工具。

   ![image](https://github.com/user-attachments/assets/d9b44b49-5524-4374-a406-3e03cdce0d15)

3. **扫描网络：** 点击“Scan Network”按钮查找连接到您本地网络的设备。
4. **选择目标：** 从列表中选择您想要攻击的设备。

    ![image](https://github.com/user-attachments/assets/94dd733a-2660-44b2-b28f-7c9583da935e)

6. **开始攻击：** 输入期望的每秒数据包数量，然后点击“Start ARP Attack”开始操作。

## 故障排查

**问题**：如果你遇到以下错误信息：

`Failed to scan network: Sniffing and sending packets is not available at layer2: winpcap is not installed. You may use conf.L3socket or comg.L3socket6 to access layer 3.`

**解决方案**：这个错误是因为你的系统中没有安装 `WinPcap`。要解决这个问题，你需要：

1. **安装 Npcap**：`Npcap` 是 `WinPcap` 的现代替代品，兼容大多数需要 `WinPcap` 的应用程序。你可以从 [Npcap 的官方网站](https://nmap.org/npcap/) 下载并安装 `Npcap`。

这样可以帮助用户在遇到这个错误时知道如何进行故障排查并解决问题。

## 免责声明

此工具仅用于教育目的。仅应在您拥有明确许可的网络上使用。在未授权的网络上使用是非法且不道德的。请负责任地使用，并始终将改善网络安全放在首位。
