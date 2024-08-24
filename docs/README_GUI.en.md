[中文](README_GUI.zh.md)

# ARP Attack Tool

## Introduction

This tool is designed to help you understand network security by demonstrating ARP spoofing attacks. It provides an easy-to-use graphical interface for scanning and attacking devices on your local network. Perfect for educational purposes and gaining insights into network vulnerabilities.

## Download

To get started, download the latest version of the ARP Attack GUI Tool from the [Releases](https://github.com/ystemsrx/Arp-Attack-tool/releases) section. Look for the `.exe` file to run the application directly on your Windows machine.

**Important:** This tool requires Nmap[(v1.0)](https://github.com/ystemsrx/Arp-Attack-tool/releases/tag/1.0) to be installed on your system. Please visit [Nmap's official download page](https://nmap.org/download.html) and select the version suitable for your operating system. For users using version 2.0 and above, there is no need to download and install this tool.

## Usage

1. **Run the Application:** Double-click the downloaded `.exe` file to launch the ARP Attack GUI Tool.
   ![image](https://github.com/user-attachments/assets/4a86936d-bbb7-4e46-b836-7787e8a6b9d2)

2. **Scan Network:** Click on "Scan Network" to find devices connected to your local network.
3. **Select Targets:** Choose the devices you want to attack by selecting them from the list.
   ![image](https://github.com/user-attachments/assets/e36076ae-a894-4337-a51b-419caebea47c)

4. **Start Attack:** Enter the desired packets per second and click "Start ARP Attack" to begin the operation.

## Troubleshooting

**Issue**: If you encounter the following error message:

`Failed to scan network: Sniffing and sending packets is not available at layer2: winpcap is not installed. You may use conf.L3socket or comg.L3socket6 to access layer 3.`

**Solution**: This error occurs because `WinPcap` is not installed on your system. To resolve this issue, you have to:

**Install Npcap**: Npcap is a modern replacement for WinPcap and is compatible with most applications that require WinPcap. You can download and install Npcap from [Npcap's official website](https://nmap.org/npcap/).

## Disclaimer

This tool is intended for educational purposes only. It should only be used on networks where you have explicit permission. Unauthorized use on networks that do not belong to you is illegal and unethical. Use responsibly and always prioritize improving network security.
