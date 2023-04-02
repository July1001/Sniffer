from PyQt5.QtWidgets import *
from scapy.all import *
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import *
from scapy.layers.inet import *

from MainWindow_UI import *

interface = ""
clicked_row = 0
pkt_index = 0
sniff_count = 0
sniff_array = []
flag = 0
sniff_filter = ""

stop_sniff_event = threading.Event()
pause_sniff_event = threading.Event()


# 时间戳转为格式化的时间字符串
def timestamp2time(timestamp):
    time_array = time.localtime(timestamp)
    mytime = time.strftime("%H:%M:%S", time_array)
    return mytime


class Main_UI(Sniff_UI, QMainWindow):
    stop_sniff_event = threading.Event()

    def __init__(self):
        super(Main_UI, self).__init__()
        self.setupUi(self)

    def begin_sniff(self):
        global flag
        global pkt_index
        global sniff_count
        global sniff_array
        if flag == 1:  # 保存完之后重新开始
            self.model.clear()
            pkt_index = 0
            sniff_count = 0
            sniff_array = []
            flag = 0

            sniffer_thread = threading.Thread(target=self.sniffer)
            sniffer_thread.setDaemon(True)
            sniffer_thread.start()

            self.model.setHorizontalHeaderLabels(['编号', '时间', '源地址', '目的地址', '协议', '长度', '信息'])
            self.tableView.setColumnWidth(0, 40)
            self.tableView.setColumnWidth(1, 100)
            self.tableView.setColumnWidth(2, 150)
            self.tableView.setColumnWidth(3, 150)
            self.tableView.setColumnWidth(4, 50)
            self.tableView.setColumnWidth(5, 50)
            self.tableView.setColumnWidth(6, 400)
            self.pushButton_start.setDisabled(True)
            self.pushButton_pause.setDisabled(False)
            self.pushButton_stop.setDisabled(False)
            self.actionbaocun.setDisabled(True)
            self.comboBox_select.setDisabled(True)
            self.pushButton_4.setDisabled(True)
        else:
            sniffer_thread = threading.Thread(target=self.sniffer)
            sniffer_thread.setDaemon(True)
            sniffer_thread.start()
            self.pushButton_start.setDisabled(True)
            self.pushButton_pause.setDisabled(False)
            self.pushButton_stop.setDisabled(False)
            self.actionbaocun.setDisabled(True)
            self.comboBox_select.setDisabled(True)
            self.pushButton_4.setDisabled(True)

    def pause_sniff(self):
        self.stop_sniff_event.set()
        self.pushButton_start.setDisabled(False)
        self.pushButton_pause.setDisabled(True)
        self.pushButton_stop.setDisabled(False)
        self.actionbaocun.setDisabled(True)
        self.comboBox_select.setDisabled(False)
        self.pushButton_4.setDisabled(False)

    def stop_sniff(self):
        self.stop_sniff_event.set()
        self.pushButton_start.setDisabled(False)
        self.pushButton_pause.setDisabled(True)
        self.pushButton_stop.setDisabled(True)
        self.actionbaocun.setDisabled(False)
        self.comboBox_select.setDisabled(False)
        self.pushButton_4.setDisabled(False)

    def set_BPF(self):
        global sniff_filter
        global pkt_index
        global sniff_count
        global sniff_array
        self.stop_sniff_event.set()
        bpf = self.lineEdit_BPF.text().lower()
        sniff_filter = bpf

        self.model.clear()
        pkt_index = 0
        sniff_count = 0
        sniff_array = []

        sniffer_thread = threading.Thread(target=self.sniffer)
        sniffer_thread.setDaemon(True)
        sniffer_thread.start()

        self.model.setHorizontalHeaderLabels(['编号', '时间', '源地址', '目的地址', '协议', '长度', '信息'])
        self.tableView.setColumnWidth(0, 40)
        self.tableView.setColumnWidth(1, 100)
        self.tableView.setColumnWidth(2, 150)
        self.tableView.setColumnWidth(3, 150)
        self.tableView.setColumnWidth(4, 50)
        self.tableView.setColumnWidth(5, 50)
        self.tableView.setColumnWidth(6, 400)
        self.pushButton_start.setDisabled(True)
        self.pushButton_pause.setDisabled(False)
        self.pushButton_stop.setDisabled(False)
        self.actionbaocun.setDisabled(True)
        self.comboBox_select.setDisabled(True)
        self.pushButton_4.setDisabled(True)

    def choose_protocol(self):
        global sniff_filter
        global pkt_index
        global sniff_count
        global sniff_array
        self.stop_sniff_event.set()
        protocol = self.comboBox_select.currentText().lower()
        if protocol == "ipv4":
            protocol = "ip"
        sniff_filter = protocol
        self.lineEdit_BPF.clear()
        self.lineEdit_BPF.setText(protocol)

        pkt_index = 0
        sniff_count = 0
        sniff_array = []

        sniffer_thread = threading.Thread(target=self.sniffer)
        sniffer_thread.setDaemon(True)
        sniffer_thread.start()

        self.model.clear()
        self.model.setHorizontalHeaderLabels(['编号', '时间', '源地址', '目的地址', '协议', '长度', '信息'])
        self.tableView.setColumnWidth(0, 40)
        self.tableView.setColumnWidth(1, 100)
        self.tableView.setColumnWidth(2, 150)
        self.tableView.setColumnWidth(3, 150)
        self.tableView.setColumnWidth(4, 50)
        self.tableView.setColumnWidth(5, 50)
        self.tableView.setColumnWidth(6, 400)
        self.pushButton_start.setDisabled(True)
        self.pushButton_pause.setDisabled(False)
        self.pushButton_stop.setDisabled(False)
        self.actionbaocun.setDisabled(True)
        self.comboBox_select.setDisabled(True)
        self.pushButton_4.setDisabled(True)

    def open_pkt(self):
        global pkt_index
        global sniff_count
        global sniff_array
        global flag
        filename, is_open = QFileDialog.getOpenFileName(self.centralwidget, 'open file', '.')
        if is_open:
            flag = 1
            print(filename)
            pkt_index = 0
            sniff_count = 0
            sniff_array = []
            sniff_array = scapy.utils.rdpcap(filename)

            self.model.clear()
            self.model.setHorizontalHeaderLabels(['编号', '时间', '源地址', '目的地址', '协议', '长度', '信息'])
            self.tableView.setColumnWidth(0, 40)
            self.tableView.setColumnWidth(1, 100)
            self.tableView.setColumnWidth(2, 150)
            self.tableView.setColumnWidth(3, 150)
            self.tableView.setColumnWidth(4, 50)
            self.tableView.setColumnWidth(5, 50)
            self.tableView.setColumnWidth(6, 400)

            for packet in sniff_array:
                realTime = timestamp2time(packet.time)
                if Ether in packet:
                    src = packet[Ether].src
                    dst = packet[Ether].dst
                    type = packet[Ether].type
                    types = {0x0800: 'IPv4', 0x0806: 'ARP', 0x86dd: 'IPv6', 0x88cc: 'LLDP', 0x891D: 'TTE'}
                    if type in types:
                        proto = types[type]
                    else:
                        proto = 'LOOP'  # 协议
                    # IP
                    if proto == 'IPv4':
                        protos = {1: 'ICMP', 2: 'IGMP', 4: 'IP', 6: 'TCP', 8: 'EGP', 9: 'IGP', 17: 'UDP', 41: 'IPv6',
                                  50: 'ESP',
                                  89: 'OSPF'}
                        src = packet[IP].src
                        dst = packet[IP].dst
                        proto = packet[IP].proto
                        if proto in protos:
                            proto = protos[proto]
                    # TCP
                    if TCP in packet:
                        protos_tcp = {80: 'Http', 443: 'Https', 23: 'Telnet', 21: 'Ftp', 20: 'ftp_data', 22: 'SSH',
                                      25: 'SMTP'}
                        sport = packet[TCP].sport
                        dport = packet[TCP].dport
                        # 获取端口信息
                        if sport in protos_tcp:
                            proto = protos_tcp[sport]
                        elif dport in protos_tcp:
                            proto = protos_tcp[dport]
                    elif UDP in packet:
                        if packet[UDP].sport == 53 or packet[UDP].dport == 53:
                            proto = 'DNS'
                else:
                    return

                length = len(packet)  # 长度
                info = packet.summary()  # 信息
                item1 = QStandardItem(str(pkt_index))
                item2 = QStandardItem(str(realTime))
                item3 = QStandardItem(src)
                item4 = QStandardItem(dst)
                item5 = QStandardItem(proto)
                item6 = QStandardItem(str(length))
                item7 = QStandardItem(info)
                self.model.setItem(pkt_index, 0, item1)
                self.model.setItem(pkt_index, 1, item2)
                self.model.setItem(pkt_index, 2, item3)
                self.model.setItem(pkt_index, 3, item4)
                self.model.setItem(pkt_index, 4, item5)
                self.model.setItem(pkt_index, 5, item6)
                self.model.setItem(pkt_index, 6, item7)
                pkt_index = pkt_index + 1

    def save_pkt(self):
        global sniff_array
        global flag
        filename, is_open = QFileDialog.getSaveFileName(self.centralwidget, 'save file', "test.pcap")
        if is_open:
            print(filename)
            wrpcap(filename[0], sniff_array)
            flag = 1
            self.pushButton_start.setDisabled(False)
            self.pushButton_pause.setDisabled(True)
            self.pushButton_stop.setDisabled(True)
            self.actionbaocun.setDisabled(True)
        else:
            self.stop_sniff_event.set()
            self.pushButton_start.setDisabled(False)
            self.pushButton_pause.setDisabled(True)
            self.pushButton_stop.setDisabled(True)
            self.actionbaocun.setDisabled(False)

    def show_details(self):
        global sniff_array
        global clicked_row
        clicked_row = self.tableView.currentIndex().row()
        self.text_details.clear()
        details = sniff_array[clicked_row].show(dump=True)
        self.text_details.setPlainText(details)
        self.text_content.clear()
        content = hexdump(sniff_array[clicked_row], dump=True)
        self.text_content.setPlainText(content)

    def sniffer(self):
        global sniff_filter
        self.stop_sniff_event.clear()
        sniff(prn=lambda x: self.pkt_sniff(x),
              stop_filter=(lambda x: self.stop_sniff_event.is_set()), filter=sniff_filter, iface=interface)

    def pkt_sniff(self, packet):
        realTime = timestamp2time(packet.time)
        global pkt_index
        global sniff_array
        sniff_array.append(packet)
        # for p in packet:
        #     p.show()

        if Ether in packet:
            src = packet[Ether].src
            dst = packet[Ether].dst
            type = packet[Ether].type
            types = {0x0800: 'IPv4', 0x0806: 'ARP', 0x86dd: 'IPv6', 0x88cc: 'LLDP', 0x891D: 'TTE'}
            if type in types:
                proto = types[type]
            else:
                proto = 'LOOP'  # 协议
            # IP
            if proto == 'IPv4':
                protos = {1: 'ICMP', 2: 'IGMP', 4: 'IP', 6: 'TCP', 8: 'EGP', 9: 'IGP', 17: 'UDP', 41: 'IPv6', 50: 'ESP',
                          89: 'OSPF'}
                src = packet[IP].src
                dst = packet[IP].dst
                proto = packet[IP].proto
                if proto in protos:
                    proto = protos[proto]
            # TCP
            if TCP in packet:
                protos_tcp = {80: 'Http', 443: 'Https', 23: 'Telnet', 21: 'Ftp', 20: 'ftp_data', 22: 'SSH', 25: 'SMTP'}
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                # 获取端口信息
                if sport in protos_tcp:
                    proto = protos_tcp[sport]
                elif dport in protos_tcp:
                    proto = protos_tcp[dport]
            elif UDP in packet:
                if packet[UDP].sport == 53 or packet[UDP].dport == 53:
                    proto = 'DNS'
        else:
            return

        length = len(packet)  # 长度
        info = packet.summary()  # 信息
        item1 = QStandardItem(str(pkt_index))
        item2 = QStandardItem(str(realTime))
        item3 = QStandardItem(src)
        item4 = QStandardItem(dst)
        item5 = QStandardItem(proto)
        item6 = QStandardItem(str(length))
        item7 = QStandardItem(info)
        self.model.setItem(pkt_index, 0, item1)
        self.model.setItem(pkt_index, 1, item2)
        self.model.setItem(pkt_index, 2, item3)
        self.model.setItem(pkt_index, 3, item4)
        self.model.setItem(pkt_index, 4, item5)
        self.model.setItem(pkt_index, 5, item6)
        self.model.setItem(pkt_index, 6, item7)
        pkt_index = pkt_index + 1


def start_main(select_interface):
    global interface
    interface = select_interface
    main_window = Main_UI()
    main_window.show()
