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
import numpy


class CheckIp(object):

    def __init__(self, thd_sum=32, record_dir='record'):
        self.start_time = time.time()
        self.dt = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
        self.thd_sum = thd_sum
        self.sem = threading.Semaphore(self.thd_sum)
        self.record_dir = record_dir
        self.basedir = os.path.dirname(os.path.abspath(__file__))
        self.record_dir = os.path.join(self.basedir, record_dir)

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

    @staticmethod
    def sum_check_result(csv_dir):
        try:
            read_csv_file = os.path.join(csv_dir, 'check_ip.csv')
            result_csv_file = os.path.join(csv_dir, 'check_sum.csv')
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


class RunThreading(threading.Thread):
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
    def __init__(self):
        threading.Thread.__init__(self)
        self.csv_headers = ['ip', 'xmt', 'rcv']
        self.time_stramp = datetime.datetime.now().strftime('%Y%m%d%H%M%S%f')
        self.thd_num = threading.Semaphore(32)
        self.record_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), self.time_stramp)
        os.mkdir(self.record_dir)

    def run(self):
        # 先写入IP记录的CSV 头部
        with open(os.path.join(self.record_dir, 'check_ip.csv'), 'a+') as f_csv:
            csv_ops = csv.writer(f_csv)
            csv_ops.writerow(self.csv_headers)
        f_csv.close()

        threads = [RunThreading(ip=ip, num=self.thd_num, r_dir=self.time_stramp) for ip in CheckIp.create_ip_list()]
        for t in threads:
            t.start()
        for t in threads:
            t.join()


if __name__ == '__main__':
    # csv_headers = ['ip', 'xmt', 'rcv']
    # time_stramp = datetime.datetime.now().strftime('%Y%m%d%H%M%S%f')
    # thd_num = threading.Semaphore(32)
    # record_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), time_stramp)
    # os.mkdir(record_dir)




    # try:
    #     read_csv_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'check_ip.csv')
    #     result_csv_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'check_sum.csv')
    #     _csv_headers = ['IP', 'Send Packages', 'Receive Packages', 'Loss %']
    #     df = pandas.DataFrame(pandas.read_csv(read_csv_file))
    #     ip_list = list(set(df.ip.values))
    #     with open(result_csv_file, 'w+') as f_sum:
    #         csv_ops = csv.writer(f_sum)
    #         csv_ops.writerow(_csv_headers)
    #         for ip in ip_list:
    #             xmt_sum = (df.loc[df["ip"] == ip].head())['xmt'].sum()
    #             rcv_sum = (df.loc[df["ip"] == ip].head())['rcv'].sum()
    #             csv_ops.writerow([ip, xmt_sum, rcv_sum, "{:.2f}%".format((xmt_sum - rcv_sum) / xmt_sum * 100)])
    # except Exception as e:
    #     raise str(e)

    MainThreading().run()