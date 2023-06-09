# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'MainWindow.ui'
#
# Created by: PyQt5 UI code generator 5.15.4
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.

import sys
import threading

import scapy.utils
from PyQt5.QtWidgets import QFileDialog
from scapy.all import *
# from sniffer import *
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.Qt import (QSplitter)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QStandardItemModel, QStandardItem
import time

from scapy.layers.inet import TCP, IP, UDP
from scapy.layers.l2 import Ether

interface = "WLAN"
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


class Sniff_UI(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("mainWindow")
        MainWindow.resize(1087, 860)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.pushButton_start = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_start.setGeometry(QtCore.QRect(10, 10, 93, 28))
        self.pushButton_start.setObjectName("pushButton_start")
        self.pushButton_pause = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_pause.setGeometry(QtCore.QRect(120, 10, 93, 28))
        self.pushButton_pause.setObjectName("pushButton_pause")
        self.pushButton_stop = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_stop.setGeometry(QtCore.QRect(230, 10, 93, 28))
        self.pushButton_stop.setObjectName("pushButton_stop")
        self.lineEdit_BPF = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit_BPF.setGeometry(QtCore.QRect(10, 50, 841, 31))
        self.lineEdit_BPF.setObjectName("lineEdit_BPF")
        self.comboBox_select = QtWidgets.QComboBox(self.centralwidget)
        self.comboBox_select.setGeometry(QtCore.QRect(860, 50, 101, 31))
        self.comboBox_select.setObjectName("comboBox_select")
        self.comboBox_select.addItem("")
        self.comboBox_select.addItem("")
        self.comboBox_select.addItem("")
        self.comboBox_select.addItem("")
        self.comboBox_select.addItem("")
        self.comboBox_select.addItem("")
        self.comboBox_select.addItem("")
        self.pushButton_4 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_4.setGeometry(QtCore.QRect(970, 50, 101, 31))
        self.pushButton_4.setObjectName("pushButton_4")

        self.text_details = QtWidgets.QTextEdit(self.centralwidget)
        self.text_details.setGeometry(QtCore.QRect(10, 470, 1065, 171))
        self.text_details.setObjectName("text_details")

        self.text_content = QtWidgets.QTextEdit(self.centralwidget)
        self.text_content.setGeometry(QtCore.QRect(10, 650, 1065, 151))
        self.text_content.setObjectName("text_content")

        self.tableView = QtWidgets.QTableView(self.centralwidget)
        self.tableView.setGeometry(QtCore.QRect(10, 90, 1065, 371))
        self.tableView.setDragEnabled(False)
        self.tableView.setObjectName("tableView")

        self.model = QStandardItemModel()
        # 设置水平方向的头标签文本内容
        self.model.setHorizontalHeaderLabels(['编号', '时间', '源地址', '目的地址', '协议', '长度', '信息'])

        # 实例化表格视图，设置模型为自定义的模型
        self.tableView.setModel(self.model)
        # 设置行列高宽随内容变化
        self.tableView.setColumnWidth(0, 40)
        self.tableView.setColumnWidth(1, 100)
        self.tableView.setColumnWidth(2, 150)
        self.tableView.setColumnWidth(3, 150)
        self.tableView.setColumnWidth(4, 50)
        self.tableView.setColumnWidth(5, 50)
        self.tableView.setColumnWidth(6, 400)
        # self.tableView.resizeColumnsToContents()
        self.tableView.resizeRowsToContents()
        # 水平方向标签拓展剩下的窗口部分，填满表格
        self.tableView.horizontalHeader().setStretchLastSection(True)
        # 水平方向，表格大小拓展到适当的尺寸
        # self.tableView.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tableView.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)  # 不可编辑
        self.tableView.setAlternatingRowColors(True)  # 颜色交替
        self.tableView.verticalHeader().setVisible(False)  # 隐藏垂直标题

        self.pushButton_pause.raise_()
        self.pushButton_stop.raise_()
        self.lineEdit_BPF.raise_()
        self.comboBox_select.raise_()
        self.pushButton_4.raise_()
        self.text_details.raise_()
        self.text_content.raise_()
        self.pushButton_start.raise_()
        self.tableView.raise_()
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1087, 26))
        self.menubar.setObjectName("menubar")
        self.menu = QtWidgets.QMenu(self.menubar)
        self.menu.setObjectName("menu")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)
        self.actiondakai = QtWidgets.QAction(MainWindow)
        self.actiondakai.setObjectName("actiondakai")
        self.actionbaocun = QtWidgets.QAction(MainWindow)
        self.actionbaocun.setObjectName("actionbaocun")
        self.menu.addAction(self.actiondakai)
        self.menu.addAction(self.actionbaocun)
        self.menubar.addAction(self.menu.menuAction())

        self.retranslateUi(MainWindow)

        self.pushButton_start.clicked.connect(lambda: MainWindow.begin_sniff())
        self.pushButton_pause.clicked.connect(lambda: MainWindow.pause_sniff())
        self.pushButton_stop.clicked.connect(lambda: MainWindow.stop_sniff())
        self.actionbaocun.triggered.connect(lambda: MainWindow.save_pkt())
        self.tableView.clicked.connect(lambda: MainWindow.show_details())
        self.comboBox_select.currentIndexChanged.connect(lambda: MainWindow.choose_protocol())
        self.pushButton_4.clicked.connect(lambda: MainWindow.set_BPF())
        self.actiondakai.triggered.connect(lambda: MainWindow.open_pkt())

        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.pushButton_start.setText(_translate("MainWindow", "开始"))
        self.pushButton_pause.setText(_translate("MainWindow", "暂停"))
        self.pushButton_stop.setText(_translate("MainWindow", "停止"))
        self.comboBox_select.setItemText(0, _translate("MainWindow", ""))
        self.comboBox_select.setItemText(1, _translate("MainWindow", "TCP"))
        self.comboBox_select.setItemText(2, _translate("MainWindow", "UDP"))
        self.comboBox_select.setItemText(3, _translate("MainWindow", "ICMP"))
        self.comboBox_select.setItemText(4, _translate("MainWindow", "ARP"))
        self.comboBox_select.setItemText(5, _translate("MainWindow", "IPv4"))
        self.comboBox_select.setItemText(6, _translate("MainWindow", "IPv6"))
        self.pushButton_4.setText(_translate("MainWindow", "确定"))
        self.menu.setTitle(_translate("MainWindow", "文件"))
        self.actiondakai.setText(_translate("MainWindow", "打开"))
        self.actionbaocun.setText(_translate("MainWindow", "保存"))

    # stop_sniff_event = threading.Event()
    #
    # def begin_sniff(self):
    #     global flag
    #     global pkt_index
    #     global sniff_count
    #     global sniff_array
    #     if flag == 1:  # 保存完之后重新开始
    #         self.model.clear()
    #         pkt_index = 0
    #         sniff_count = 0
    #         sniff_array = []
    #         flag = 0
    #
    #         sniffer_thread = threading.Thread(target=self.sniffer)
    #         sniffer_thread.setDaemon(True)
    #         sniffer_thread.start()
    #
    #         self.model.setHorizontalHeaderLabels(['编号', '时间', '源地址', '目的地址', '协议', '长度', '信息'])
    #         self.tableView.setColumnWidth(0, 40)
    #         self.tableView.setColumnWidth(1, 100)
    #         self.tableView.setColumnWidth(2, 150)
    #         self.tableView.setColumnWidth(3, 150)
    #         self.tableView.setColumnWidth(4, 50)
    #         self.tableView.setColumnWidth(5, 50)
    #         self.tableView.setColumnWidth(6, 400)
    #         self.pushButton_start.setDisabled(True)
    #         self.pushButton_pause.setDisabled(False)
    #         self.pushButton_stop.setDisabled(False)
    #         self.actionbaocun.setDisabled(True)
    #         self.comboBox_select.setDisabled(True)
    #         self.pushButton_4.setDisabled(True)
    #     else:
    #         sniffer_thread = threading.Thread(target=self.sniffer)
    #         sniffer_thread.setDaemon(True)
    #         sniffer_thread.start()
    #         self.pushButton_start.setDisabled(True)
    #         self.pushButton_pause.setDisabled(False)
    #         self.pushButton_stop.setDisabled(False)
    #         self.actionbaocun.setDisabled(True)
    #         self.comboBox_select.setDisabled(True)
    #         self.pushButton_4.setDisabled(True)
    #
    # def pause_sniff(self):
    #     self.stop_sniff_event.set()
    #     self.pushButton_start.setDisabled(False)
    #     self.pushButton_pause.setDisabled(True)
    #     self.pushButton_stop.setDisabled(False)
    #     self.actionbaocun.setDisabled(True)
    #     self.comboBox_select.setDisabled(False)
    #     self.pushButton_4.setDisabled(False)
    #
    # def stop_sniff(self):
    #     self.stop_sniff_event.set()
    #     self.pushButton_start.setDisabled(False)
    #     self.pushButton_pause.setDisabled(True)
    #     self.pushButton_stop.setDisabled(True)
    #     self.actionbaocun.setDisabled(False)
    #     self.comboBox_select.setDisabled(False)
    #     self.pushButton_4.setDisabled(False)
    #
    # def set_BPF(self):
    #     global sniff_filter
    #     global pkt_index
    #     global sniff_count
    #     global sniff_array
    #     self.stop_sniff_event.set()
    #     bpf = self.lineEdit_BPF.text().lower()
    #     sniff_filter = bpf
    #
    #     self.model.clear()
    #     pkt_index = 0
    #     sniff_count = 0
    #     sniff_array = []
    #
    #     sniffer_thread = threading.Thread(target=self.sniffer)
    #     sniffer_thread.setDaemon(True)
    #     sniffer_thread.start()
    #
    #     self.model.setHorizontalHeaderLabels(['编号', '时间', '源地址', '目的地址', '协议', '长度', '信息'])
    #     self.tableView.setColumnWidth(0, 40)
    #     self.tableView.setColumnWidth(1, 100)
    #     self.tableView.setColumnWidth(2, 150)
    #     self.tableView.setColumnWidth(3, 150)
    #     self.tableView.setColumnWidth(4, 50)
    #     self.tableView.setColumnWidth(5, 50)
    #     self.tableView.setColumnWidth(6, 400)
    #     self.pushButton_start.setDisabled(True)
    #     self.pushButton_pause.setDisabled(False)
    #     self.pushButton_stop.setDisabled(False)
    #     self.actionbaocun.setDisabled(True)
    #     self.comboBox_select.setDisabled(True)
    #     self.pushButton_4.setDisabled(True)
    #
    # def choose_protocol(self):
    #     global sniff_filter
    #     global pkt_index
    #     global sniff_count
    #     global sniff_array
    #     self.stop_sniff_event.set()
    #     protocol = self.comboBox_select.currentText().lower()
    #     if protocol == "ipv4":
    #         protocol = "ip"
    #     sniff_filter = protocol
    #     self.lineEdit_BPF.clear()
    #     self.lineEdit_BPF.setText(protocol)
    #
    #     pkt_index = 0
    #     sniff_count = 0
    #     sniff_array = []
    #
    #     sniffer_thread = threading.Thread(target=self.sniffer)
    #     sniffer_thread.setDaemon(True)
    #     sniffer_thread.start()
    #
    #     self.model.clear()
    #     self.model.setHorizontalHeaderLabels(['编号', '时间', '源地址', '目的地址', '协议', '长度', '信息'])
    #     self.tableView.setColumnWidth(0, 40)
    #     self.tableView.setColumnWidth(1, 100)
    #     self.tableView.setColumnWidth(2, 150)
    #     self.tableView.setColumnWidth(3, 150)
    #     self.tableView.setColumnWidth(4, 50)
    #     self.tableView.setColumnWidth(5, 50)
    #     self.tableView.setColumnWidth(6, 400)
    #     self.pushButton_start.setDisabled(True)
    #     self.pushButton_pause.setDisabled(False)
    #     self.pushButton_stop.setDisabled(False)
    #     self.actionbaocun.setDisabled(True)
    #     self.comboBox_select.setDisabled(True)
    #     self.pushButton_4.setDisabled(True)
    #
    # def open_pkt(self):
    #     global pkt_index
    #     global sniff_count
    #     global sniff_array
    #     global flag
    #     filename, is_open = QFileDialog.getOpenFileName(self.centralwidget, 'open file', '.')
    #     if is_open:
    #         flag = 1
    #         print(filename)
    #         pkt_index = 0
    #         sniff_count = 0
    #         sniff_array = []
    #         sniff_array = scapy.utils.rdpcap(filename)
    #
    #         self.model.clear()
    #         self.model.setHorizontalHeaderLabels(['编号', '时间', '源地址', '目的地址', '协议', '长度', '信息'])
    #         self.tableView.setColumnWidth(0, 40)
    #         self.tableView.setColumnWidth(1, 100)
    #         self.tableView.setColumnWidth(2, 150)
    #         self.tableView.setColumnWidth(3, 150)
    #         self.tableView.setColumnWidth(4, 50)
    #         self.tableView.setColumnWidth(5, 50)
    #         self.tableView.setColumnWidth(6, 400)
    #
    #         for packet in sniff_array:
    #             realTime = timestamp2time(packet.time)
    #             if Ether in packet:
    #                 src = packet[Ether].src
    #                 dst = packet[Ether].dst
    #                 type = packet[Ether].type
    #                 types = {0x0800: 'IPv4', 0x0806: 'ARP', 0x86dd: 'IPv6', 0x88cc: 'LLDP', 0x891D: 'TTE'}
    #                 if type in types:
    #                     proto = types[type]
    #                 else:
    #                     proto = 'LOOP'  # 协议
    #                 # IP
    #                 if proto == 'IPv4':
    #                     protos = {1: 'ICMP', 2: 'IGMP', 4: 'IP', 6: 'TCP', 8: 'EGP', 9: 'IGP', 17: 'UDP', 41: 'IPv6',
    #                               50: 'ESP',
    #                               89: 'OSPF'}
    #                     src = packet[IP].src
    #                     dst = packet[IP].dst
    #                     proto = packet[IP].proto
    #                     if proto in protos:
    #                         proto = protos[proto]
    #                 # TCP
    #                 if TCP in packet:
    #                     protos_tcp = {80: 'Http', 443: 'Https', 23: 'Telnet', 21: 'Ftp', 20: 'ftp_data', 22: 'SSH',
    #                                   25: 'SMTP'}
    #                     sport = packet[TCP].sport
    #                     dport = packet[TCP].dport
    #                     # 获取端口信息
    #                     if sport in protos_tcp:
    #                         proto = protos_tcp[sport]
    #                     elif dport in protos_tcp:
    #                         proto = protos_tcp[dport]
    #                 elif UDP in packet:
    #                     if packet[UDP].sport == 53 or packet[UDP].dport == 53:
    #                         proto = 'DNS'
    #             else:
    #                 return
    #
    #             length = len(packet)  # 长度
    #             info = packet.summary()  # 信息
    #             item1 = QStandardItem(str(pkt_index))
    #             item2 = QStandardItem(str(realTime))
    #             item3 = QStandardItem(src)
    #             item4 = QStandardItem(dst)
    #             item5 = QStandardItem(proto)
    #             item6 = QStandardItem(str(length))
    #             item7 = QStandardItem(info)
    #             self.model.setItem(pkt_index, 0, item1)
    #             self.model.setItem(pkt_index, 1, item2)
    #             self.model.setItem(pkt_index, 2, item3)
    #             self.model.setItem(pkt_index, 3, item4)
    #             self.model.setItem(pkt_index, 4, item5)
    #             self.model.setItem(pkt_index, 5, item6)
    #             self.model.setItem(pkt_index, 6, item7)
    #             pkt_index = pkt_index + 1
    #
    # def save_pkt(self):
    #     global sniff_array
    #     global flag
    #     filename, is_open = QFileDialog.getSaveFileName(self.centralwidget, 'save file', "test.pcap")
    #     if is_open:
    #         print(filename)
    #         wrpcap(filename[0], sniff_array)
    #         flag = 1
    #         self.pushButton_start.setDisabled(False)
    #         self.pushButton_pause.setDisabled(True)
    #         self.pushButton_stop.setDisabled(True)
    #         self.actionbaocun.setDisabled(True)
    #     else:
    #         self.stop_sniff_event.set()
    #         self.pushButton_start.setDisabled(False)
    #         self.pushButton_pause.setDisabled(True)
    #         self.pushButton_stop.setDisabled(True)
    #         self.actionbaocun.setDisabled(False)
    #
    # def show_details(self):
    #     global sniff_array
    #     global clicked_row
    #     clicked_row = self.tableView.currentIndex().row()
    #     self.text_details.clear()
    #     details = sniff_array[clicked_row].show(dump=True)
    #     self.text_details.setPlainText(details)
    #     self.text_content.clear()
    #     content = hexdump(sniff_array[clicked_row], dump=True)
    #     self.text_content.setPlainText(content)
    #
    # def sniffer(self):
    #     global sniff_filter
    #     self.stop_sniff_event.clear()
    #     sniff(prn=lambda x: self.pkt_sniff(x),
    #           stop_filter=(lambda x: self.stop_sniff_event.is_set()), filter=sniff_filter, iface=interface)
    #
    # def pkt_sniff(self, packet):
    #     realTime = timestamp2time(packet.time)
    #     global pkt_index
    #     global sniff_array
    #     sniff_array.append(packet)
    #     # for p in packet:
    #     #     p.show()
    #
    #     if Ether in packet:
    #         src = packet[Ether].src
    #         dst = packet[Ether].dst
    #         type = packet[Ether].type
    #         types = {0x0800: 'IPv4', 0x0806: 'ARP', 0x86dd: 'IPv6', 0x88cc: 'LLDP', 0x891D: 'TTE'}
    #         if type in types:
    #             proto = types[type]
    #         else:
    #             proto = 'LOOP'  # 协议
    #         # IP
    #         if proto == 'IPv4':
    #             protos = {1: 'ICMP', 2: 'IGMP', 4: 'IP', 6: 'TCP', 8: 'EGP', 9: 'IGP', 17: 'UDP', 41: 'IPv6', 50: 'ESP',
    #                       89: 'OSPF'}
    #             src = packet[IP].src
    #             dst = packet[IP].dst
    #             proto = packet[IP].proto
    #             if proto in protos:
    #                 proto = protos[proto]
    #         # TCP
    #         if TCP in packet:
    #             protos_tcp = {80: 'Http', 443: 'Https', 23: 'Telnet', 21: 'Ftp', 20: 'ftp_data', 22: 'SSH', 25: 'SMTP'}
    #             sport = packet[TCP].sport
    #             dport = packet[TCP].dport
    #             # 获取端口信息
    #             if sport in protos_tcp:
    #                 proto = protos_tcp[sport]
    #             elif dport in protos_tcp:
    #                 proto = protos_tcp[dport]
    #         elif UDP in packet:
    #             if packet[UDP].sport == 53 or packet[UDP].dport == 53:
    #                 proto = 'DNS'
    #     else:
    #         return
    #
    #     length = len(packet)  # 长度
    #     info = packet.summary()  # 信息
    #     item1 = QStandardItem(str(pkt_index))
    #     item2 = QStandardItem(str(realTime))
    #     item3 = QStandardItem(src)
    #     item4 = QStandardItem(dst)
    #     item5 = QStandardItem(proto)
    #     item6 = QStandardItem(str(length))
    #     item7 = QStandardItem(info)
    #     self.model.setItem(pkt_index, 0, item1)
    #     self.model.setItem(pkt_index, 1, item2)
    #     self.model.setItem(pkt_index, 2, item3)
    #     self.model.setItem(pkt_index, 3, item4)
    #     self.model.setItem(pkt_index, 4, item5)
    #     self.model.setItem(pkt_index, 5, item6)
    #     self.model.setItem(pkt_index, 6, item7)
    #     pkt_index = pkt_index + 1


# def start_main(select_interface):
#     global interface
#     interface = select_interface
    # sniff_ui=Sniff_UI()
    # sniff_ui.show()

    # app = QtWidgets.QApplication(sys.argv)
    # widget = QtWidgets.QMainWindow()
    # gui1 = Sniff_UI()
    # gui1.show()
    # gui1.setupUi(widget)
    # widget.show()
    # sys.exit(app.exec_())


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    widget = QtWidgets.QMainWindow()
    gui1 = Sniff_UI()
    # gui1.set_matplotlib()
    gui1.setupUi(widget)
    widget.show()
    sys.exit(app.exec_())

# main("WLAN")