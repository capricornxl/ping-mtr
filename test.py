#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @FileName：     test.py
# @Software:      
# @Author:         Leven Xiang
# @Mail:           xiangle0109@outlook.com
# @Date：          2019/7/9 11:20

import subprocess
import platform
import configparser
import os
import datetime
import sys
import time


def run_path():
    return os.path.split(os.path.realpath(__file__))[0]


if __name__ == '__main__':
    ip = '114.114.114.114'
    config_file = os.path.join(run_path(), 'config1')
    if os.path.exists(config_file) and os.path.isfile(config_file):
        pass
    else:
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
