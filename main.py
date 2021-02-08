# -*- coding:utf-8 -*-
# Author：LukcinSven
# Form_pc: Home_win10
# Creat_Date：2020-03-10
# Topic_for：_For_Webug4.0_Scanner_


import socket
import requests
import re
import platform
import time
import os
import datetime
import sys

# 0 Get the cookie

# 1This function is used for port scanning
def get_ip_status(ip, port):

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.connect((ip, port))
        print('{0} port {1} is open'.format(ip, port))

    except Exception as err:
        print('{0} port {1} is not open'.format(ip, port))

    finally:
        server.close()


def scan_mode(flag) -> bool:
    risk_port_list = [20, 21, 22, 23, 80, 143, 110, 443, 389, 445, ]

    if flag:
        print("》》》Star high risk port scan...")
        for port in risk_port_list:
            get_ip_status(host, port)

    else:
        print("》》》Star all port scan...")
        for port in range(20, 1000):
             get_ip_status(host, port)


# 2This function is used for directory traversal
def dir_trave(ip):
    print("》》》Star dir_trave...")
    url = 'http://'+ip
    r = requests.get(url)

    # 利用 re
    matchs = re.findall(r"(?<=href=\").+?(?=\")|(?<=href=\').+?(?=\')", r.text)
    for link in matchs:
        print(link)
        time.sleep(1)

    print()

# 3This function is used for system_os identify
def platform_identify():
    print("》》》Star platform_identify...")
    os_id = platform.uname()
    print(os_id)
    print()
# 4This function is used for database_ver identify
def database_identify(ip):
    print("》》》Srar database_identify...")
    time.sleep(2)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    database_port = [1433, 1521, 3306, 6379, ]

    for port in database_port:
        try:
            server.connect((ip, port))
            if port == 1433:
                print("{} database is: SQLServer".format(ip))

            if port == 1521:
                print("{} database is: Oracle".format(ip))
            if port == 3306:
                print("{} database is: Mysql".format(ip))
                print()
            if port == 6379:
                print("{} database is Redis".format(ip))

        except Exception as err:
            time.sleep(0.2)
            database_flag = False
    server.close()


# 5This function is used for SQL injection detection
def sql_inject_identify(host):
    print("》》》Star sql_inject_identify...")

    # url = 'http://www.baidu.com'
    url = 'http://'+host+'/control/sqlinject/bool_injection.php?id=1'

    headers = {'User-Agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.116 Mobile Safari/537.36',
               'Cookie': 'PHPSESSID=ufr8rcg74m093a44p44ppni111'


               }
    r = requests.get(url, headers=headers)
    r.encoding = r.apparent_encoding
    rcl = r.content
    # print("{} 该网页大小为 {}".format(url, len(r.content)))
    # print(r.text)

    url_1 = url+'%27'
    try:
        r_1 = requests.get(url_1, headers=headers)
        rcl_1 = r_1.content
        # print("{} 该网页大小为 {}".format(url_1, len(r_1.content)))
        r_1.encoding = r_1.apparent_encoding
    except Exception as link_err:
        rcl_1 = rcl


    if(rcl==rcl_1):
        print("Test_the_url:{}".format(url))
        print("Result: Safe, This Website inexistence SQL_INJECTION Bug")

    else:
        print("Test_the_url:{}".format(url))
        print("Result: Warning, This Website exist SQL_INJECTION Bug ")
        print()

# 6This function is used for XSS injection detection
def xss_bug_identify(host):
    print("》》》Star xss_bug_identify...")
    # 9
    url = 'http://'+host+'/control/xss/xss_1.php?id=1'

    headers = {
        'User-Agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.116 Mobile Safari/537.36',
        'Cookie': 'PHPSESSID=ufr8rcg74m093a44p44ppni111'

        }


    url_1 = url[:-1]
    xss_test_url = url_1+'<script>alert(/Xss_Bug_Exist/)</script>'

    r = requests.get(url, headers=headers)
    # print(r.text)
    print(r.status_code)
    try:
        r_1 = requests.get(xss_test_url, headers=headers)
        if r_1.status_code ==200:
            print("Test_the_url:{}".format(url))
            print("After XSS INJECT URL: {}, response_code: {}".format(xss_test_url, r_1.status_code))
            print("Result: Warning, This Website exist XSS_INJECTION Bug ")
            print()

    except Exception as xss_er:
        print("{} is safe ".format(url))

# 7This function is used for weak_password
def weak_password_identify(host):
    print("》》》Star weak_password_identify...")

    url = 'http://'+host+'/control/sqlinject/universal_passwd.php'

    headers = {
        'User-Agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.116 Mobile Safari/537.36',
        'Cookie': 'PHPSESSID=ufr8rcg74m093a44p44ppni111',

    }

    data = {
        'username': 'admin',
        'password': 'admin',
    }

    r_1 = requests.get(url, headers)
    print(r_1.status_code)
    # print(r_1.text)


    r_2 = requests.post(url, data=data,  )

    r_2.encoding =r_2.apparent_encoding
    if r_2.status_code ==200:
        print("Test_the_url:{}".format(url))
        print("Result: Warning, This Website exist WEAK_PASSWORD Bug ")
        print()


def link_check(ip):
    print("Test connect the host...")
    check_flag = False
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.connect((ip, 80))
        print('{} connect successful'.format(ip))
        print()
        check_flag = True
        return check_flag
    except Exception as err:
        print('{}connect fail'.format(ip))
        print("Please Check the Host Value")
        print()
        return check_flag
    finally:
        server.close()

def os_mkdir(path):

    dir_flag = os.path.exists(path)

    if not dir_flag:
        os.mkdir(path)
        print("build done")

    else:
        print("dir is exist")


if __name__ == '__main__':

    #dir_trave(host)
    # platform_identify()
    # get_ip_status(host, port=3306)
    # database_identify(host)
    # sql_inject()
    # xss_bug_identify()
    # weak_password_identify()
    # path = r"C:\Webug_Scan_Report\test5.txt"
    # f = open(path, 'a+')
    # temp_out = sys.stdout
    # sys.stdout = f
    # sys.stdout = temp_out

    print("***************************************************************")
    print("*** Bugweb4.0 Scan_all**********Author:LukinSven***************")
    print("*** Please check the VM and Webug4.0 PHP Sever already open!***")
    print("***************************************************************")

    path = r"C:\Webug_Scan_Report"
    os_mkdir(path)
    #
    # now_time = datetime.datetime.now().strftime("%F-%H_%M_%S")
    # os.chdir(path)
    # save_name = now_time + '_Scan_Report.txt'
    # os.rename("test.txt", save_name)


    while(1):
        print("Please input the host_ip:Like 192.168.181.130")
        host = input("enter q exit, waiting input: ")
        # print(host)

        if host =='q':
            exit(7)

        check_code = link_check(host)

        if(check_code):
            # print("Please Select port scan mode,enter 1 is high risk port scan,0 is all port scan")

            test_path = r"C:\Webug_Scan_Report\test.txt"
            f = open(test_path, 'a+')
            sys.stdout = f

            #scan_flag = input("Enter q exit, waiting input: ")
            scan_flag =True
            scan_mode(scan_flag)

            dir_trave(host)
            platform_identify()
            database_identify(host)

            sql_inject_identify(host)
            xss_bug_identify(host)
            weak_password_identify(host)

            try:
                f.close()
                now_time = datetime.datetime.now().strftime("%F-%H_%M_%S")
                os.chdir(path)
                save_name = now_time + '_Scan_Report.txt'
                os.rename("test.txt", save_name)
                f.close()
            except Exception as file_err:
                pass

            exit(1)

        if host =='q':
            exit(7)

        else:
            pass
