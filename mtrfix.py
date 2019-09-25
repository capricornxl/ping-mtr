# -*- coding: utf-8 -*-
import subprocess
import datetime
import time
import threading
from threading import current_thread
from timerthead import runtimer
import re
import csv
import sys


class CheckIp(object):

    def __init__(self, runtime=3600):

        self.start_time = time.time()
        self.dt = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
        self.dt1 = datetime.datetime.now().strftime('%Y%m%d%H%M')
        self.infocompile = re.compile(".*")
        self.csv_headers = ['ip', 'xmt', 'rcv', 'loss']
        self.runtime = runtime

    @staticmethod
    def create_ip_list():
        with open("IPlist.txt", "r") as IPlists:
            ip_readlines = IPlists.readlines()
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

    @runtimer()
    def run_ping(self):
        """
        ping 检测
        :return:
        """
        try:
            with open('check_ip_result.csv', 'w+') as f_csv, open('check_ip_result.txt', 'w+') as f_ping, \
                    open('mtr_ip_result.txt', 'w+') as f_mtr:
                csv_ops = csv.writer(f_csv)
                csv_ops.writerow(self.csv_headers)
                for ip in self.create_ip_list():
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


if __name__ == '__main__':
    try:
        if sys.argv[1:]:
            if sys.argv[1] == 'ping' and sys.argv[2] == 'sum':
                ops = CheckIp(runtime=3600)
                ops.run_ping()
            elif sys.argv[1] == 'ping' and sys.argv[2]:
                sec = sys.argv[2]
                ops = CheckIp(runtime=sec)
                ops.run_ping()
        else:
            ops = CheckIp(runtime=3600)
            ops.run_ping()

    except Exception as e:
        print(str(e))