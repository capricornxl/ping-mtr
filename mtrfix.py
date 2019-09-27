# -*- coding: utf-8 -*-
import subprocess
import datetime
import time
import timeout_decorator
import threading
import re
import csv
import os
import sys
import pandas
from getopt import *


def cprint(color, message):
    """
    :param color: 消息颜色
    :param message 消息内容
    :return: None
    """
    colors = {'red': 31, 'green': 32, 'yellow':33, 'blue': 34, 'dark_green': 36, 'default': 37}
    if color in colors:
        fore = colors[color]
    else:
        fore = 37
    color = '\033[%d;%dm' % (1, fore)
    print('%s%s\033[0m' % (color, message))


class CheckIp(object):

    def __init__(self, record_dir='record'):
        self.start_time = time.time()
        self.dt = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
        self.record_dir = record_dir

    @staticmethod
    def create_ip_list():
        with open(os.path.join(os.path.dirname(os.path.abspath('__file__')), "IPlist.txt"), "r") as f_ip_lists:
            ip_readlines = f_ip_lists.readlines()
            ip_list = []
            for ip in ip_readlines:
                if ip.strip('\n'):
                    ip_list.append(ip.strip())
            return ip_list

    @staticmethod
    def ping_ip(ip):
        """
        :param ip: IP地址
        :return: DICT code：命令执行状态，result：结果内容列表
        """
        result_list = []
        try:
            ping_result = subprocess.Popen(['fping', '-c', '5', '-p', '1000', ip, '-a'], stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, encoding='gbk')
            stdout, stderr = ping_result.communicate()
            exit_code = ping_result.returncode
            for line in stdout, stderr:
                if line:
                    result_list.append(line.strip('\n'))
            return dict({'code': exit_code, 'result': result_list})
        except Exception as e:
            raise str(e)

    @staticmethod
    def mtr_ip(ip):
        """
        :param ip: IP地址
        :return: DICT code：命令执行状态，result：结果内容列表
        """
        result_list = []
        try:
            mtr_result = subprocess.Popen(['mtr', '-r', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                          encoding='gbk')
            stdout, stderr = mtr_result.communicate()
            exit_code = mtr_result.returncode
            for line in stdout, stderr:
                if line:
                    result_list.append(line.strip('\n'))
            return dict({'code': exit_code, 'result': result_list})
        except Exception as e:
            raise str(e)

    @staticmethod
    def collect_xmt_rcv(data):
        """
        :param data:  传入的fping单条数据，
        :return: 字典对象
        """
        try:
            compile_a = re.compile(r"xmt/rcv/%loss = [0-9]\d*/[0-9]\d*/(\d|[0-9]\d|100)(\.\d{1,2})?%")
            compile_b = re.compile(r"(?P<xmt>[0-9]\d*)/(?P<rcv>[0-9]\d*)")
            data_a = re.search(compile_a, data).group()
            data_b = re.search(compile_b, data_a)
            return dict({"xmt": data_b.group('xmt'), "rcv": data_b.group('rcv')})
        except Exception as e:
            raise str(e)

    def run_ping(self, ip):
        try:
            with open(os.path.join(self.record_dir, 'check_ip.csv'), 'a+') as f_csv, \
                    open(os.path.join(self.record_dir, 'check_ip.txt'), 'a+') as f_ping, \
                    open(os.path.join(self.record_dir, 'mtr_ip.txt'), 'a+') as f_mtr:
                csv_ops = csv.writer(f_csv)
                print_ip_result = self.ping_ip(ip)
                for ping_line in print_ip_result['result']:
                    if ping_line:
                        print(self.dt, '\t', ping_line, file=f_ping)
                        xmt_rcv = self.collect_xmt_rcv(ping_line)
                        csv_ops.writerow([ip, xmt_rcv['xmt'], xmt_rcv['rcv']])
                if print_ip_result['code'] != 0:
                    mtr_ip_result = self.mtr_ip(ip)
                    if mtr_ip_result['code'] == 0:
                        print(self.dt, '\t', ip, ' Run mtr：', file=f_mtr)
                        for mtr_line in mtr_ip_result['result']:
                            if mtr_line:
                                print(mtr_line, file=f_mtr)
                    else:
                        print(self.dt, '\t', ip, ' run mtr error')
            f_mtr.close()
            f_ping.close()
            f_csv.close()
        except Exception as e:
            print(str(e))

    def sum_check_result(self):
        try:
            read_csv_file = os.path.join(self.record_dir, 'check_ip.csv')
            result_csv_file = os.path.join(self.record_dir, 'check_sum.csv')
            _csv_headers = ['ip', 'xmt', 'rcv', 'loss']
            df = pandas.DataFrame(pandas.read_csv(read_csv_file))
            ip_list = list(set(df.ip.values))
            with open(result_csv_file, 'w+') as f_sum:
                csv_ops = csv.writer(f_sum)
                csv_ops.writerow(_csv_headers)
                for ip in ip_list:
                    xmt_sum = (df.loc[df["ip"] == ip].head())['xmt'].sum()
                    rcv_sum = (df.loc[df["ip"] == ip].head())['rcv'].sum()
                    csv_ops.writerow([ip, xmt_sum, rcv_sum, "{:.2f}%".format((xmt_sum - rcv_sum) / xmt_sum * 100)])
            f_sum.close()
        except Exception as e:
            raise str(e)


class PingThreading(threading.Thread):
    def __init__(self, ip=None, num=None, r_dir='record'):
        threading.Thread.__init__(self)
        self._ip = ip
        self._thd_num = num
        self._dir = r_dir

    def run(self):
        with self._thd_num:
            ops = CheckIp(record_dir=self._dir)
            ops.run_ping(ip=self._ip)


class MainThreading(threading.Thread):
    def __init__(self, thd_num, timeout=None, record_dir='record'):
        threading.Thread.__init__(self)
        self.csv_headers = ['ip', 'xmt', 'rcv']
        self.time_stramp = datetime.datetime.now().strftime('%Y%m%d%H%M%S%f')
        self.thd_num = thd_num
        self.timeout = timeout
        self.record_dir = record_dir
        os.mkdir(self.record_dir)

    def run(self):
        try:
            # 先写入IP记录的CSV 头部
            with open(os.path.join(self.record_dir, 'check_ip.csv'), 'a+') as f_csv:
                csv_ops = csv.writer(f_csv)
                csv_ops.writerow(self.csv_headers)
            f_csv.close()
            if self.timeout is None:
                n = 1
                threads = [PingThreading(ip=ip, num=self.thd_num, r_dir=self.record_dir) for ip in
                           CheckIp.create_ip_list()]
                cprint("green", "主线程总计[%d]个任务" % len(threads))
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()
                    print('第%d个线程完成...' % n)
                    n += 1

            else:
                n, r = 1, 1
                while True:
                    cprint("red", '开始第%d次循环...' % r)
                    threads = [PingThreading(ip=ip, num=self.thd_num, r_dir=self.record_dir) for ip in
                               CheckIp.create_ip_list()]
                    cprint("green", "主线程总计[%d]个任务" % len(threads))
                    for t in threads:
                        t.start()
                    for t in threads:
                        t.join()
                        print('第%d个线程完成...' % n)
                        n += 1
                    r += 1
                    time.sleep(1)

        except Exception as e:
            print(str(e))


if __name__ == '__main__':
    thd_num = 32
    summary = False
    runtime = None
    argv = sys.argv[1:]
    time_stramp = datetime.datetime.now().strftime('%Y%m%d%H%M%S%f')
    record_dir = os.path.join(os.path.dirname(os.path.abspath('__file__')), time_stramp)

    try:
        opts, args = getopt(argv, "hn:t:s")
    except GetoptError:
        cprint("green", """参数说明：
    -n <number> 指定线程并发数，单位数字。
    -t <number> 指定循环运行时间，单位秒。不指定-t，只执行一次。
    -s 是否对数据进行统计
    """)
        sys.exit(1)
    except Exception as e:
        cprint("red", '异常：%s' % str(e))

    for opt, arg in opts:
        if opt in ('-h',):
            cprint("green", """参数说明：
    -n <number> 指定线程并发数，单位数字。
    -t <number> 指定循环运行时间，单位秒。不指定-t，只执行一次。
    -s 是否对数据进行统计
    """)
            sys.exit()
        elif opt in ('-n',):
            thd_num = int(arg)
        elif opt in ('-s',):
            summary = True
        elif opt in ('-t',):
            runtime = int(arg)

    num = threading.Semaphore(thd_num)
    if runtime is not None:
        cprint("blue", "本次运行指定运行时长[%d]秒..." % runtime)

    run = MainThreading(thd_num=num, timeout=runtime, record_dir=record_dir)
    cprint("blue", "主线程开始：")
    run.setDaemon(True)
    run.start()
    run.join(timeout=runtime)
    cprint("green", "所有任务己完成...")
    run.isAlive()
    cprint("blue", "主线程结束...\n")

    if summary:
        cprint("blue", "开始汇总数据：")
        CheckIp(record_dir=record_dir).sum_check_result()
        cprint("blue", "汇总数据完成...")

    cprint("dark_green", "所有数据在目录[%s]" % record_dir)