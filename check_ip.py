#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @FileName：     check_ip.py
# @Software:
# @Author:         Leven Xiang
# @Mail:           xiangle0109@outlook.com
# @Date：          2019/7/9 11:20

"""
===========================================================================
    IP header info from RFC791
      -> http://tools.ietf.org/html/rfc791)

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Version|  IHL  |Type of Service|          Total Length         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Identification        |Flags|      Fragment Offset    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Time to Live |    Protocol   |         Header Checksum       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Source Address                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Destination Address                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    ===========================================================================
    ICMP Echo / Echo Reply Message header info from RFC792
      -> http://tools.ietf.org/html/rfc792

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |     Type      |     Code      |          Checksum             |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |           Identifier          |        Sequence Number        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |     Data ...
        +-+-+-+-+-

    ===========================================================================
"""

import subprocess
import datetime
import threading
import configparser
import csv
import os
import sys
import pandas
from getopt import getopt, GetoptError
import select
import socket
import struct
import time
import signal
import traceback


ICMP_ECHO_REQUEST = 8
DEFAULT_TIMEOUT = 1
DEFAULT_COUNT = 5
DEFAULT_WAIT = 500


def signal_handler(signum, frame):
    cprint("red", "接收到Ctrl+C，等待线程退出.. %d" % signum)
    if summary:
        cprint("blue", "开始汇总数据: ")
        CheckIp(record_dir=record_dir).sum_check_result()
        cprint("blue", "汇总数据完成...")

    cprint("dark_green", "所有数据在目录[%s]" % record_dir)
    end_time = time.time()
    cprint("blue", "耗时： %s秒 " % round((end_time - start_time), 3))
    sys.exit(0)


def run_path():
    return os.path.split(os.path.realpath(__file__))[0]


DEFAULT_IP_FILE = os.path.join(run_path(), 'iplist')


def cprint(color, message):
    """
    :param color: 消息颜色
    :param message 消息内容
    :return: None
    """
    colors = {'red': 31, 'green': 32, 'yellow': 33, 'blue': 34, 'dark_green': 36, 'default': 37}
    if color in colors:
        fore = colors[color]
    else:
        fore = 37
    color = '\033[%d;%dm' % (1, fore)
    print('%s%s\033[0m' % (color, message))


class Pinger(object):
    def __init__(self, host, count=DEFAULT_COUNT, timeout=DEFAULT_TIMEOUT, wait=DEFAULT_WAIT):
        """
        :param host:  IP地址或域名
        :param count: ping次数
        :param timeout: icmp超时，单位秒
        :param wait: 每次ping的间隔，单位ms
        """
        self.target_host = host
        self.count = count
        self.timeout = timeout
        self.wait = wait

    @staticmethod
    def do_checksum(source_string):
        """
        来自 ping.c 的 in_cksum（） 功能
        正常情况下，将在字符串上充当一系列 16 位 int（主机包装），但是网络数据是big-endian，主机一般是 little-endian
        :param source_string:
        :return:
        """
        sums = 0
        max_count = (len(source_string) / 2) * 2
        count = 0
        # 成对处理字节(解码为短ints)
        while count < max_count:
            val = source_string[count + 1] * 256 + source_string[count]
            sums = sums + val
            sums = sums & 0xffffffff
            count = count + 2

        # 处理最后一个字节(奇数字节)
        # 在这种情况下，Endianness应该是无关紧要的
        if max_count < len(source_string):
            sums = sums + ord(source_string[len(source_string) - 1])
            # 将sum截断为32位(与ping.c不同)，它使用带符号的int，但是ping中不太可能出现溢出。
            sums = sums & 0xffffffff
        # 添加高位16bit到低位16bit
        sums = (sums >> 16) + (sums & 0xffff)
        # 如果存在，从上面结果中添加
        sums = sums + (sums >> 16)
        # 反转和截断到16位
        answer = ~sums & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)
        return answer

    @staticmethod
    def receive_icmp(sock, id, timeout):
        """
        从socket 接收 ping
        """
        # 等待数据包返回或循环超时
        while True:
            time_remaining = timeout
            start_t = time.time()
            readable = select.select([sock], [], [], time_remaining)
            time_spent = (time.time() - start_t)
            # Timeout
            if not readable[0]:
                return
            time_received = time.time()
            recv_packet, addr = sock.recvfrom(1024)
            icmp_header = recv_packet[20:28]
            type, code, checksum, packet_id, sequence = struct.unpack("bbHHh", icmp_header)
            if packet_id == id:
                bytes_In_double = struct.calcsize("d")
                time_sent = struct.unpack("d", recv_packet[28:28 + bytes_In_double])[0]
                return time_received - time_sent
            time_remaining = time_remaining - time_spent
            if time_remaining <= 0:
                return

    def send_icmp(self, sock, check_id):
        """
        :param sock: socket icmp instance
        :param check_id:
        :return:
        """
        # 获取主机名，如果是域名会解析成IP
        target_addr = socket.gethostbyname(self.target_host)
        my_checksum = 0
        # 生成校验和为0的报文heder。
        header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, my_checksum, check_id, 1)

        bytes_In_double = struct.calcsize("d")
        data = (192 - bytes_In_double) * "Q"
        data = struct.pack("d", time.time()) + bytes(data.encode('utf-8'))
        # 计算报头和数据的校验和
        my_checksum = self.do_checksum(header + data)
        # 正确的校验和
        header = struct.pack(
            "bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), check_id, 1
        )
        # 计算并生成报头和数据的校验和
        packet = header + data
        # 端口号与ICMP无关
        sock.sendto(packet, (target_addr, 1))

    def ping_once(self):
        icmp = socket.getprotobyname("icmp")
        try:
            sock_fun = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        except socket.error as se:
            if se.errno == 1:
                se.msg += "Socket ICMP报文只能通过超级管理用户进程发送"
                raise socket.error(se.msg)
        except Exception as Ee:
            cprint("red", "ping_once: %s" % str(Ee))
            print(traceback.format_exc())
        get_id = os.getpid() & 0xFFFF
        self.send_icmp(sock_fun, get_id)
        delay = self.receive_icmp(sock_fun, get_id, self.timeout)
        return delay

    @staticmethod
    def get_loss(sent, rcvd):
        if sent > 0:
            loss = ((sent - rcvd) / sent) * 100.0
            return loss

    def ping(self):
        sent = 0
        rcvd = 0
        status = "Success"
        for i in range(self.count):
            try:
                sent += 1
                # unit: Second
                delay = self.ping_once()
            except socket.gaierror as ge:
                status = "Error"
                print("Ping failed. (socket error: '%s')" % str(ge))
                print(traceback.format_exc())
                break
            if delay is None:
                pass
            else:
                rcvd += 1
                time.sleep(self.wait / 1000)
        if rcvd == 0:
            status = "Failed"
        rtime = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
        return dict({"Status": status, "Time": rtime, "Sent": sent, "Rcvd": rcvd, "Loss": "{:.2f}%" .format(self.get_loss(sent, rcvd))})


class CheckIp(object):
    def __init__(self, record_dir=run_path()):
        self.start_time = time.time()
        self.dt = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
        self.record_dir = record_dir

    @staticmethod
    def ping_check(ip):
        """
        :param ip: IP地址
        :return: DICT code: 命令执行状态，result: 结果内容列表
        """
        result_list = []
        try:
            pstart_time = time.time()
            c = configparser.ConfigParser()
            c.read(os.path.join(run_path(), 'config'))
            count = int(c.get('ping', 'count'))
            wait = int(c.get('ping', 'wait'))
            timeout = int(c.get('ping', 'timeout'))
            ping_result = Pinger(host=ip, count=count, wait=wait, timeout=timeout).ping()
            pend_time = time.time()
            cprint("blue", "IP：%s 执行[ping_check]耗时： %s秒 " % (ip, round((pend_time - pstart_time), 3)))
            return ping_result
        except configparser.Error as ce:
            cprint("red", "config配置文件中[ping]配置参数存在错误：")
            print(str(ce))
            print(traceback.format_exc())
            sys.exit(1)
        except Exception as pe:
            cprint("red", "ping_check: %s" % str(pe))
            print(traceback.format_exc())

    @staticmethod
    def mtr_check(ip):
        """
        :param ip: IP地址
        :return: DICT code: 命令执行状态，result: 结果内容列表
        """
        result_list = []
        try:
            mstart_time = time.time()
            c = configparser.ConfigParser()
            c.read(os.path.join(run_path(), 'config'))
            command = [c.get('mtr', 'path'), ip] + c.get('mtr', 'paras').split(' ')
            mtr_result = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='gbk')
            stdout, stderr = mtr_result.communicate()
            exit_code = mtr_result.returncode
            for line in stdout, stderr:
                if line:
                    result_list.append(line.strip('\n'))
            mend_time = time.time()
            cprint("blue", "IP：%s 执行[mtr_check]耗时： %s秒 " % (ip, round((mend_time - mstart_time), 3)))
            return dict({'Status': exit_code, 'result': result_list})
        except configparser.Error as ce:
            cprint("red", "config配置文件中[ping]配置参数存在错误：")
            print(str(ce))
            sys.exit(1)
        except FileNotFoundError as se:
            print("可执行路径中未找到mtr，请确认mtr是否己安装或指定的mtr路径有误。")
            sys.exit(1)
        except subprocess.TimeoutExpired as se:
            print("IP:%s, subprocess.TimeoutExpired" % ip)
            print(str(se))
        except subprocess.CalledProcessError as se:
            print("IP:%s, subprocess.CalledProcessError" % ip)
            print(str(se))
        except subprocess.SubprocessError as se:
            print(str(se))
            print(traceback.format_exc())
        except Exception as me:
            cprint("red", "mtr_check: %s" % str(me))
            print(traceback.format_exc())

    def run_ping(self, ip):
        try:
            rstart_time = time.time()
            with open(os.path.join(self.record_dir, 'check-ip-record.csv'), 'a+') as f_csv, \
                    open(os.path.join(self.record_dir, 'mtr-ip-check.log'), 'a+') as f_mtr:
                csv_ops = csv.writer(f_csv)
                ping_ip_result = self.ping_check(ip)
                if ping_ip_result:
                    csv_ops.writerow([ping_ip_result['Time'], ip, ping_ip_result['Sent'], ping_ip_result['Rcvd'], ping_ip_result['Loss']])
                if ping_ip_result['Status'] is not "Success":
                    mtr_ip_result = self.mtr_check(ip)
                    if mtr_ip_result['Status'] == 0:
                        print('-' * 120, file=f_mtr)
                        print(self.dt, '\t', ip, ' 执行Mtr的结果: ', file=f_mtr)
                        for mtr_line in mtr_ip_result['result']:
                            if mtr_line:
                                print(mtr_line, file=f_mtr)
                        print('-' * 120, file=f_mtr)
                    else:
                        print(self.dt, '\t', ip, ' 执行Mtr出错...')
                        print('-' * 120, file=f_mtr)
            f_mtr.close()
            f_csv.close()
            rend_time = time.time()
            cprint("blue", "IP：%s的所在子线程总任务执行[ping_check、mtr_check]完毕，耗时： %s秒 " % (ip, round((rend_time - rstart_time), 3)))
        except FileNotFoundError:
            cprint("red", "IP: %s, 写入文件时出现FileNotFoundError" % ip)
        except Exception as re:
            cprint("red", "run_ping: %s" % str(re))
            print(traceback.format_exc())

    def sum_check_result(self):
        try:
            read_csv_file = os.path.join(self.record_dir, 'check-ip-record.csv')
            result_csv_file = os.path.join(self.record_dir, 'check-ip-sum.csv')
            _csv_headers = ['IP', 'Sent', 'Rcvd', 'Loss']
            df = pandas.DataFrame(pandas.read_csv(read_csv_file))
            ip_list = list(set(df.IP.values))
            with open(result_csv_file, 'w+') as f_sum:
                csv_ops = csv.writer(f_sum)
                csv_ops.writerow(_csv_headers)
                for ip in ip_list:
                    sent_sum = int((df.loc[df["IP"] == ip].head())['Sent'].sum())
                    rcvd_sum = int((df.loc[df["IP"] == ip].head())['Rcvd'].sum())
                    csv_ops.writerow([ip, sent_sum, rcvd_sum, "{:.2f}%".format((sent_sum - rcvd_sum) / sent_sum * 100)])
            f_sum.close()
        except Exception as scre:
            cprint("red", "sum_check_result: %s" % str(scre))
            print(traceback.format_exc())


def create_ip_list(file):
    try:
        cstart_time = time.time()
        with open(file, "r") as f_ip_lists:
            ip_readlines = f_ip_lists.readlines()
            ip_list = []
            for ip in ip_readlines:
                if ip.strip('\n'):
                    ip_list.append(ip.strip())
            cend_time = time.time()
            cprint("blue", "读取文件创建IP列表，耗时： %s秒 " % round((cend_time - cstart_time), 3))
            return ip_list

    except Exception as cile:
        cprint("red", "create_ip_list: %s" % str(cile))
        print(traceback.format_exc())


class PingThreading(threading.Thread):
    def __init__(self, ip=None, num=None, r_dir='record'):
        threading.Thread.__init__(self)
        self._ip = ip
        self._thd_num = num
        self._dir = r_dir

    def run(self):
        with self._thd_num:
            print("IP:%s，开始子线程：%s" % (self._ip, threading.current_thread().ident))
            ops = CheckIp(record_dir=self._dir)
            ops.run_ping(ip=self._ip)
            print("IP:%s，等待子线程：%s 执行完毕" % (self._ip, threading.current_thread().ident))


class MainThreading(threading.Thread):
    def __init__(self, thd_num, timeout=None, record_dir='record', ip_file=DEFAULT_IP_FILE):
        threading.Thread.__init__(self)
        self.csv_headers = ['Time', 'IP', 'Sent', 'Rcvd', 'Loss']
        self.time_stramp = datetime.datetime.now().strftime('%Y%m%d%H%M%S%f')
        self.thd_num = thd_num
        self.timeout = timeout
        self.record_dir = record_dir
        self.ip_file = ip_file
        os.mkdir(self.record_dir)

    def run(self):
        try:
            with open(os.path.join(self.record_dir, 'check-ip-record.csv'), 'a+') as f_csv:
                csv_ops = csv.writer(f_csv)
                csv_ops.writerow(self.csv_headers)
            f_csv.close()

            if self.timeout is None:
                count = 1
                threads = [PingThreading(ip=ip, num=self.thd_num, r_dir=self.record_dir) for ip in create_ip_list(self.ip_file)]
                cprint("green", "主线程总计[%d]个任务" % len(threads))
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()
                    print('第%d个线程完成...' % count)
                    count += 1
            else:
                r_count = 1
                while True:
                    cprint("red", '开始第%d次循环...' % r_count)
                    threads = [PingThreading(ip=ip, num=self.thd_num, r_dir=self.record_dir) for ip in create_ip_list(self.ip_file)]
                    cprint("green", "主线程总计[%d]个任务" % len(threads))
                    for t in threads:
                        t.start()
                    count = 1
                    for t in threads:
                        t.join()
                        print('第%d个线程完成...' % count)
                        count += 1
                    r_count += 1
                    time.sleep(1)

        except Exception as e:
            cprint("red", str(e))
            print(traceback.format_exc())


if __name__ == '__main__':
    config_file = os.path.join(run_path(), 'config')
    if os.path.exists(config_file) and os.path.isfile(config_file):
        pass
    else:
        cprint("red", "未发现config配置，己初始化生成..")
        with open(config_file, 'w') as config_fs:
            config_fs.write("""[ping]
#ping执行次数
count = 5
#每次ping的间隔，单位毫秒
wait = 200
#每次ping的超时时间，单位秒
timeout = 1

[mtr]
#mtr程序所在路径，可以是绝对路径、相对路径
path = mtr
#mtr的参数，按实际在cmd或shell中运行时指定的写进去即可，每个参数用空格分隔
paras = -c 3 -r --no-dns
""")
    start_time = time.time()
    thd_num = 32
    summary = False
    run_time = None
    ip_file = os.path.join(run_path(), 'iplist')
    argv = sys.argv[1:]
    time_stramp = datetime.datetime.now().strftime('%Y%m%d%H%M%S%f')
    record_dir = os.path.join(run_path(), time_stramp)

    try:
        opts, args = getopt(argv, "hn:t:s")
    except GetoptError:
        cprint("green", """
    在iplist文件中写入需要检测的IP地址，每行一个
    再运行本脚本，脚本会自动对每个IP做PING检测，如果IP检测不通则会执行MTR，并记录MTR到文件。
    
    参数说明: 
    -n <number> 指定线程并发数，单位数字。
    -t <number> 指定运行时间，单位秒。不指定-t，只执行一次。（指定运行时间会在指定时间内循环对iplist列表做检测）
    -s 是否对IP ping的数据进行统计，主要统计每个IP总体的发送包、接收包，丢包率情况
    """)
        sys.exit(1)
    except Exception as e:
        cprint("red", '异常: %s' % str(e))
        print(traceback.format_exc())

    for opt, arg in opts:
        if opt in ('-h',):
            cprint("green", """
config文件是配置文件，里面有一些配置参数，可自行定义。
在iplist文件中写入需要检测的IP地址，每行一个。
脚本会自动对每个IP做PING检测，如果IP检测不通则会执行MTR，并记录MTR到文件。

参数说明: 
-n <number> 指定线程并发数，单位数字。
-t <number> 指定运行时间，单位秒。不指定-t，只执行一次。（指定运行时间会在指定时间内循环对iplist列表做检测）
-s 是否对IP ping的数据进行统计，主要统计每个IP总体的发送包、接收包，丢包率情况
""")
            sys.exit()
        elif opt in ('-n',):
            thd_num = int(arg)
        elif opt in ('-s',):
            summary = True
        elif opt in ('-t',):
            run_time = int(arg)

    num = threading.Semaphore(thd_num)
    if run_time is not None:
        cprint("blue", f"本次运行指定运行时长[{run_time:d}]秒...")
    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, signal_handler)
    run = MainThreading(thd_num=num, timeout=run_time, record_dir=record_dir)
    cprint("blue", "主线程开始: ")
    cprint("blue", "可使用Ctrl+C随时终止任务 ")
    cprint("blue", "当前线程数: %s" % thd_num)
    run.setDaemon(True)
    run.start()
    run.join(timeout=run_time)
    cprint("green", "所有任务己完成...")
    run.isAlive()
    cprint("blue", "主线程结束...\n")

    if summary:
        cprint("blue", "开始汇总数据: ")
        CheckIp(record_dir=record_dir).sum_check_result()
        cprint("blue", "汇总数据完成...")

    cprint("dark_green", "所有数据在目录[%s]" % record_dir)
    end_time = time.time()
    cprint("blue", "耗时： %s秒 " % round((end_time - start_time), 3))
