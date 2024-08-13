[中文](README.zh.md)

# ARP Attack Tool

Welcome to the ARP Attack Tool, a mischievous tool designed to let you explore the vulnerabilities of network protocols. Whether you want to play harmless pranks or understand the importance of network security, this script is your playful partner in crime (for educational purposes only, of course!).

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Disclaimer](#disclaimer)

## Overview

The script is a program that performs ARP (Address Resolution Protocol) spoofing on a network. It is intended to illustrate how network attacks can occur and to emphasize the need for robust security measures. The script allows you to temporarily disrupt a device's network connection, perfect for stopping those pesky free-loaders on your Wi-Fi or pranking your loud relatives during their gaming sessions.
There is also a PyQt5 based GUI version available.

## Features

- **Network Scanning:** Automatically scans and lists devices on your network, showing their IP and MAC addresses.
- **Manufacturer Detection:** Attempts to identify the manufacturer of each network device.
- **ARP Spoofing:** Sends spoofed ARP packets to selected devices, potentially disrupting their network connectivity.
- **Multi-threading:** Uses threads to target multiple devices simultaneously.

## Requirements

To run this script, you will need:

- Python 3.x
- The following Python packages:
  - `scapy`
  - `netifaces`
  - `requests`
  - `python-nmap`
  - `PyQt5`(Optional)

- nmap
  - Goto [nmap download link](https://nmap.org/download.html) to download the nmap version that suits your system.

For Linux user, please ensure you have root access to your network interface to execute this script.

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/arp-attack-tool.git
   cd arp-attack-script
   ```

2. **Install the required packages:**
   ```bash
   pip install -r requirements.txt
   ```
   To run the GUI version, run `pip install PyQt5` in your terminal.

## Usage

1. **Run the script:**
   ```bash
   sudo python Arp_Attack.py
   ```
   or
   ```bash
   sudo Arp_Attack_GUI.py.py
   ```

3. **Follow the prompts:**
   - The script will scan your network and display a list of online devices.
   - Enter the indices of the devices you wish to target (e.g., `0 2 4`).
   - Specify the number of packets per second you want to send.

4. **Watch the chaos unfold:**
   - The script will start sending ARP packets to the targeted devices, potentially disrupting their network connections.

## Disclaimer

This script is provided for educational purposes only. It is meant to demonstrate the vulnerabilities in network protocols and emphasize the importance of network security. Use it responsibly and only on networks where you have explicit permission. Unauthorized use of this script on networks that do not belong to you or without permission is illegal and unethical.

Have fun, learn a lot, and remember to use your powers for good!
