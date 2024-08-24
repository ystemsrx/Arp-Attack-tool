[中文](README.zh.md)

[Back to Home](https://github.com/ystemsrx/Arp-Attack-tool)

# ARP Attack Tool (GUI version)

## Overview

This project is a Python-based GUI tool designed for network scanning and executing ARP spoofing (Man-in-the-Middle) attacks. It is built using the PyQt5 framework for the graphical user interface and Scapy for network packet manipulation.

## Features

- **Network Scanning**: The tool can scan the local network to identify devices, displaying their IP, MAC address, and manufacturer information.
- **ARP Spoofing**: Users can select targets from the scanned devices list and initiate an ARP spoofing attack, sending fake ARP packets to redirect traffic.
- **Language Support**: The interface supports English and Simplified Chinese[(v2.1)](Arp_Attack_GUI_v2.1.py), allowing users to switch between the two languages.
- **Always on Top**: An option to keep the window always on top of other windows.

## Requirements

- Python 3.x
- PyQt5
- Scapy
- netifaces
- requests

## Usage

1. **Launch the Application**: Start the GUI by running the script.
![image](https://github.com/user-attachments/assets/7e242d67-c1f9-4cfa-a02b-430a3042ffdb)

2. **Scan Network**: Click the "Scan Network" button to start scanning the local network. Devices will be listed with their IP, MAC address, and manufacturer.
![image](https://github.com/user-attachments/assets/b589b207-9c7c-4d4e-a54c-163948624dc9)

3. **Select Targets**: Choose the devices you want to target by selecting them from the list.
4. **Configure Attack**: Specify the number of ARP packets to send per second.
![image](https://github.com/user-attachments/assets/68bad39d-af59-4414-84a1-0d45c6c39b26)

5. **Start Attack**: Click "Start ARP Attack" to begin the ARP spoofing attack.
6. **Stop Attack**: The attack can be stopped at any time by clicking the "Stop Attack" button.
![image](https://github.com/user-attachments/assets/149ae65e-6e0b-4b84-a9a4-0490e655f971)

## GUI Components

- **Scan Network Button**: Initiates the network scanning process.
- **Devices List**: Displays scanned devices with their respective IP and MAC addresses.
- **Target Indices**: Allows manual input of target device indices for selection.
- **Packets Per Second**: Configures the rate at which ARP packets are sent during an attack.
- **Language Switch**: Toggles between English and Simplified Chinese for the interface.
- **Always on Top Checkbox**: Keeps the window on top of other applications.

## Troubleshooting

**Issue**: If you encounter the following error message:

`Failed to scan network: Sniffing and sending packets is not available at layer2: winpcap is not installed. You may use conf.L3socket or comg.L3socket6 to access layer 3.`

**Solution**: This error occurs because `WinPcap` is not installed on your system. To resolve this issue, you have to:

**Install Npcap**: Npcap is a modern replacement for WinPcap and is compatible with most applications that require WinPcap. You can download and install Npcap from [Npcap's official website](https://nmap.org/npcap/).

## Safety Disclaimer

**This tool is intended for educational purposes only.** Unauthorized use of ARP spoofing tools on networks without explicit permission from the network owner is illegal and unethical. Always ensure you have the necessary permissions before conducting any network attacks.

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.

## Contributions

Contributions to this project are welcome. Please submit pull requests with clear descriptions and ensure your code adheres to the project's coding standards.
