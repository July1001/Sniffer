import matplotlib.pyplot as plt
from PyQt5 import QtCore, QtGui, QtWidgets
import sys

from PyQt5.QtWidgets import QDialog
import sniffer
from select_UI import *
from MainWindow_UI import *
import select_UI
import select_interface
# from select_interface import *


# from select_interface import *

class Start_UI(QDialog):

    def __init__(self, parent=None):
        super(QDialog, self).__init__(parent)
        self.ui = select_UI.Ui_MainWindow()
        self.ui.setupUi(self)
        self.draw = select_interface.draw()
        interface_list = self.draw.get_interface_list()
        for interface in interface_list:
            self.ui.comboBox_select.addItem(interface)
            self.ui.comboBox_select.setItemText(interface_list.index(interface), interface)
        # self.show_traffic()

    def start_sniff(self):
        interface = self.ui.comboBox_select.currentText()
        # print(interface)
        self.draw.stop_sniff()
        sniffer.start_main(interface)
        self.close()

    def exit_sniff(self):
        self.close()

    def show_traffic(self):
        self.draw.get_all_pkt()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    dlg = Start_UI()
    dlg.show()
    sys.exit(app.exec_())
