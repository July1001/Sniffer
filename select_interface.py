from scapy.all import *
from netifaces import interfaces
import winreg as wr
import time
import threading
import matplotlib

# matplotlib.use('Agg')
matplotlib.use('TkAgg')
# matplotlib.use('QTAgg')
import matplotlib.pyplot as plt

sniff_count = {}
stop_sniff_event = threading.Event()
stop_sniff_event1 = threading.Event()
stop_sniff_event2 = threading.Event()
thread1 = threading.Thread()
thread2 = threading.Thread()
flag = 0


# matplotlib.use('TkAgg')
# matplotlib.use('nbAgg')


# # 捕获总数
# sniff_count = 0
# # 所有捕获到的报文
# sniff_array = []

class draw():
    stop_sniff_event = threading.Event()

    def __init__(self):
        self.a = 1

    # 定义获取Windows系统网卡接口的在注册表的键值的函数
    def get_interface(self):
        key_name = {}
        id = interfaces()
        try:
            reg = wr.ConnectRegistry(None,
                                     wr.HKEY_LOCAL_MACHINE)
            reg_key = wr.OpenKey(reg,
                                 r'SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}')
        except:
            return ('路径出错或者其他问题，请仔细检查')

        for i in id:
            try:
                reg_subkey = wr.OpenKey(reg_key, i + r'\Connection')
                key_name[wr.QueryValueEx(reg_subkey, 'Name')[0]] = i
            except FileNotFoundError:
                pass
        return key_name

    def get_interface_list(self):
        iface = self.get_interface()
        interface_list = [key for key in iface]
        return interface_list

    # iface = get_interface()
    # interface_list = [key for key in iface]

    # print(len(interface_list))

    # print(interface_list[-2])
    # get_pkt()

    def pkt_info_all(self, pkt, sniff_array, interface):
        global sniff_count
        sniff_count[interface] += 1
        sniff_array.append(pkt)
        info = pkt.summary()
        # print(info)
        # pkt.show()

    def Thread_get_pkt(self, interface, fig, table):
        global stop_sniff_event1
        global sniff_count
        global flag
        sniff_array = []
        draw = threading.Thread(target=self.draw_pkt, args=(interface, table))
        draw.setDaemon(True)
        draw.start()
        # draw = self.draw_pkt(interface, table)
        # draw.start()
        self.stop_sniff_event.clear()
        sniff(prn=lambda pkt: self.pkt_info_all(pkt, sniff_array, interface),
              stop_filter=(lambda x: self.stop_sniff_event.is_set()), iface=interface, count=0)

    def draw_pkt(self, interface, table):
        global stop_sniff_event2

        line = None
        obsx = []
        obsy = []
        x = 0
        count = 0
        global sniff_count
        time1 = time.time()

        while True:
            if time.time() - time1 >= 1:
                time1 = time.time()
                x += 1
                obsx.append(x)
                obsy.append(sniff_count[interface] - count)
                # print(sniff_count[self.interface] - count)
                count = sniff_count[interface]
                if line is None:
                    line = table.plot(obsx, obsy, '-b', marker=None)[0]
                line.set_xdata(obsx)
                line.set_ydata(obsy)
                if len(obsx) < 100:
                    table.set_xlim([min(obsx), max(obsx) + 30])
                else:
                    table.set_xlim([obsx[-80], max(obsx) * 1.2])
                if len(obsy) % 10 == 0:
                    table.set_ylim([min(obsy), max(obsy) + 10])

                plt.show()
                # plt.draw()

    def get_all_pkt(self):
        global flag
        flag = 0
        interface_list = self.get_interface_list()
        # 创建一个折线图
        fig = plt.figure()
        # 设置中文语言
        plt.rcParams['font.sans-serif'] = ['SimHei']  # 显示中文标签
        plt.rcParams['axes.unicode_minus'] = False
        num = len(interface_list)
        # print(num)
        global sniff_count
        global thread1
        for interface in interface_list:
            # print(interface)
            sniff_count[interface] = 0

            index = interface_list.index(interface)
            table = fig.add_subplot(num, 1, index + 1)
            table.set_ylabel(str(interface), rotation=0, fontsize=8, labelpad=10)

            get_all_pkt = threading.Thread(target=self.Thread_get_pkt, args=(interface, fig, table))
            get_all_pkt.setDaemon(True)
            get_all_pkt.start()

        plt.show()

    def start(self):
        self.draw_start = threading.Thread(target=self.get_all_pkt)
        self.draw_start.setDaemon(True)
        self.draw_start.start()

    def stop_sniff(self):
        global flag
        flag = 1
        self.stop_sniff_event.set()
        # self.draw_start.join()
        # stop_sniff_event1.set()
        # stop_sniff_event2.set()


if __name__ == '__main__':
    a = draw()
    a.get_all_pkt()
