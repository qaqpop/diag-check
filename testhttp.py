import requests
import hashlib
import binascii
import random
import string
from hashlib import pbkdf2_hmac
import time
import threading
import logging
import sys
from datetime import datetime
import os
import argparse
import json
import subprocess
import socket

# 配置日志系统
def setup_logging():
    """设置日志配置"""
    # 创建logs目录
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    # 生成带时间戳的日志文件名
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f'logs/session_test_{timestamp}.log'
    
    # 配置日志格式
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_filename, encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger(__name__)

# 初始化日志
logger = setup_logging()

class SessionAuth:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
    
    def _generate_random_string(self, length=8):
        """
        生成指定长度的随机字符串（数字）
        """
        return ''.join(random.choices(string.digits, k=length))
    
    def _pwd_to_aes_key(self, challenge, sz_username, sz_salt, sz_pwd, iterations):
        """
        根据提供的参数生成 AES 密钥
        """
        # 第一步：计算 Secure.sha256(username + salt + password) + challenge
        combined_string = f"{sz_username}{sz_salt}{sz_pwd}"
        sha256_hash = hashlib.sha256(combined_string.encode('utf-8')).hexdigest()
        password = f"{sha256_hash}{challenge}"
        
        # 第二步：使用 PBKDF2 生成密钥
        key = pbkdf2_hmac(
            hash_name='sha256',
            password=password.encode('utf-8'),
            salt=sz_salt.encode('utf-8'),
            iterations=iterations,
            dklen=64
        )
        
        # 第三步：转换为十六进制字符串并取前128位
        hex_key = binascii.hexlify(key).decode('utf-8')
        return hex_key[:128]
    
    def get_auth_info(self, username, random_str=None):
        """
        获取认证信息（sessionID, challenge, salt, iterations）
        """
        url = f"{self.base_url}/iot/global/0-global/model/service/operate/Session/AuthInfo"
        
        if random_str is None:
            random_str = self._generate_random_string(8)
        
        data = {
            "data": {
                "username": username,
                "random": random_str
            }
        }
        
        logger.info(f"获取认证信息 - 用户名: {username}, URL: {url}")
        response = self.session.post(url, json=data)
        
        if response.status_code == 200:
            result = response.json()
            if result.get("code") == "0x00000000":
                logger.info(f"认证信息获取成功 - SessionID: {result['data']['sessionID']}")
                return result["data"]
            else:
                error_msg = f"获取认证信息失败: {result.get('errorMsg')}"
                logger.error(error_msg)
                raise Exception(error_msg)
        else:
            error_msg = f"HTTP请求失败: {response.status_code}"
            logger.error(error_msg)
            raise Exception(error_msg)
    
    def login(self, username, password):
        """
        执行登录操作（单个密码）
        """
        logger.info(f"开始登录 - 用户名: {username}")
        
        # 第一步：获取认证信息
        auth_info = self.get_auth_info(username)
        
        # 提取认证信息
        session_id = auth_info["sessionID"]
        challenge = auth_info["challenge"]
        iterations = auth_info["iterations"]
        salt = auth_info["salt"]
        
        logger.info(f"认证信息获取完成 - Challenge: {challenge[:16]}..., Salt: {salt}, Iterations: {iterations}")
        
        # 第二步：生成密码哈希
        hashed_password = self._pwd_to_aes_key(
            challenge=challenge,
            sz_username=username,
            sz_salt=salt,
            sz_pwd=password,
            iterations=iterations
        )
        
        logger.info(f"密码哈希生成完成 - 长度: {len(hashed_password)}")
        
        # 第三步：执行登录
        url = f"{self.base_url}/iot/global/0-global/model/service/operate/Session/Login"
        login_data = {
            "data": {
                "username": username,
                "password": hashed_password,
                "sessionID": session_id,
                "isSessionIDValidLongTerm": False,
                "sessionIDVersion": "V1.0",
                "isNeedSessionTag": True
            }
        }
        
        logger.info(f"发送登录请求 - URL: {url}")
        response = self.session.post(url, json=login_data)
        
        if response.status_code == 200:
            result = response.json()
            if result.get("code") == "0x00000000":
                session_tag = result.get('data', {}).get('sessionTag', '')
                logger.info(f"登录成功! - SessionTag: {session_tag[:16]}...")
                return result
            else:
                # 密码失败不打印详细日志
                raise Exception(f"登录失败: {result.get('errorMsg')}")
        else:
            # HTTP请求失败不打印详细日志
            raise Exception(f"登录请求失败: {response.status_code}")
    
    def login_with_retry(self, username, passwords):
        """
        使用多个密码尝试登录，直到成功或所有密码都尝试完毕
        
        Args:
            username: 用户名
            passwords: 密码列表
        
        Returns:
            登录成功的响应结果和成功使用的密码
        
        Raises:
            Exception: 所有密码都尝试失败后抛出异常
        """
        if not passwords:
            raise Exception("密码列表为空")
        
        logger.info(f"开始多密码重试登录 - 用户名: {username}, 密码数量: {len(passwords)}")
        
        last_error = None
        
        for idx, password in enumerate(passwords, 1):
            try:
                logger.info(f"尝试第 {idx}/{len(passwords)} 个密码")
                result = self.login(username, password)
                logger.info(f"使用第 {idx} 个密码登录成功")
                return result, password  # 返回结果和成功使用的密码
            except Exception as e:
                last_error = e
                # 密码失败不打印详细日志
                if idx < len(passwords):
                    time.sleep(1)  # 短暂延迟，避免频繁请求
        
        # 所有密码都尝试失败
        error_msg = f"所有 {len(passwords)} 个密码都尝试失败，最后错误: {last_error}"
        logger.error(error_msg)
        raise Exception(error_msg)

# 为SessionAuth添加post方法
def session_auth_post(self, url, json=None, headers=None, timeout=10):
    """为SessionAuth添加post方法"""
    if hasattr(self, 'session') and self.session:
        return self.session.post(url, json=json, headers=headers, timeout=timeout)
    else:
        raise AttributeError("SessionAuth没有可用的session对象")

# 动态添加方法到SessionAuth类
SessionAuth.post = session_auth_post

# 全局变量记录线程状态
active_threads = {}
thread_lock = threading.Lock()
base_url = {}

# 请求数据和URL对应列表

def url_get(base_url):
    request_configs = [
        # 端口
        {
            "url": f"{base_url}/iot/global/0-global/model/service/operate/NetTransDevDiag/StartNetTransDevDiag",
            "data": {
            }
            
        },
        {
            "url": f"{base_url}/iot/global/0-global/model/service/operate/NetTransDevDiag/GetNetTransDevDiagResult",
            "data": {
            }
            
        },
                {
            "url": f"{base_url}/iot/global/0-global/model/service/operate/NetTransDevDiag/GetNetTransDevDiagResult",
            "data": {
            }
            
        },
                {
            "url": f"{base_url}/iot/global/0-global/model/service/operate/NetTransDevDiag/GetNetTransDevDiagResult",
            "data": {
            }
            
        },
                {
            "url": f"{base_url}/iot/global/0-global/model/service/operate/NetTransDevDiag/GetNetTransDevDiagResult",
            "data": {
            }
            
        },
                {
            "url": f"{base_url}/iot/global/0-global/model/service/operate/NetTransDevDiag/GetNetTransDevDiagResult",
            "data": {
            }
            
        },
    ]

    request_configs_get = [
    {
        "url": f"{base_url}/iot/global/0-global/model/service/operate/L2TableMgr/MacAgeing",
    },

]

    return  request_configs, request_configs_get
# 修改 user_worker 函数以支持请求轮数参数和多密码重试
def user_worker(user_id, thread_username, passwords, base_url, original_username, max_rounds=2):
    """单个用户的工作线程"""
    try:
        # 从线程用户名中提取IP信息用于日志
        ip_info = "unknown"
        if '_' in thread_username:
            parts = thread_username.split('_')
            if len(parts) >= 2:
                # IP地址在用户名和线程号之间，需要将所有IP段用点连接
                # 格式: username_192_168_1_1_1 -> 192.168.1.1
                ip_parts = parts[1:-1]  # 排除用户名和最后的线程号
                ip_info = '.'.join(ip_parts)
        
        # 记录线程启动
        with thread_lock:
            active_threads[thread_username] = {
                'thread_id': threading.current_thread().ident,
                'start_time': datetime.now(),
                'status': 'running',
                'request_count': 0,
                'error_count': 0,
                'ip': ip_info,
                'original_username': original_username,
                'successful_password': None,  # 记录成功登录的密码
                'non_200_urls': []  # 记录非200响应的URL
            }
        
        logger.info(f"线程启动 - 用户名: {thread_username}, 原始用户名: {original_username}, IP: {ip_info}, 密码数量: {len(passwords)}")
        
        # 创建认证实例
        auth = SessionAuth(base_url)

        # 执行登录 - 使用原始用户名和多个密码重试
        result, successful_password = auth.login_with_retry(original_username, passwords)
        logger.info(f"{thread_username} 登录响应状态: {result.get('status')}")
        
        # 记录成功登录的密码
        with thread_lock:
            active_threads[thread_username]['successful_password'] = successful_password
        
        if result.get('status') != 200:
            logger.error(f"{thread_username} 登录失败，跳过后续请求")
            return
        
        # 提取sessionTag
        session_tag = None
        if isinstance(result, dict) and result.get('status') == 200:
            data = result.get('data', {})
            session_tag = data.get('sessionTag')
            if session_tag:
                logger.info(f"{thread_username} - 提取到sessionTag: {session_tag[:16]}...")
        
        request_configs = []
        request_configs_get = []
        request_configs, request_configs_get = url_get(base_url)
        
        # 准备请求头
        headers = {
            'User-Agent': 'python-requests/2.32.5',
            'Accept': '*/*',
            'Content-Type': 'application/json',
            'Connection': 'keep-alive'
        }
        
        # 添加sessionTag到请求头（如果存在）
        if session_tag:
            headers['sessionTag'] = session_tag
        
        # 循环请求
        request_count = 0
        while request_count < max_rounds:
            request_count += 1
            
            # 更新线程状态
            with thread_lock:
                active_threads[thread_username]['request_count'] = request_count
                active_threads[thread_username]['last_activity'] = datetime.now()
            
            logger.info(f"{thread_username} - 第{request_count}/{max_rounds}轮请求开始")
            
            # POST请求
            for config in request_configs:
                try:
                    url = config["url"]
                    request_data = config["data"]
                    api_name = url.split('/')[-1]
                    
                    # 为GetNetTransDevDiagResult创建专门的循环发送闭包
                    if "GetNetTransDevDiagResult".lower() in url.lower():
                        # 使用闭包捕获外部变量
                        def diag_loop():
                            """闭包函数：在130秒内循环发送GetNetTransDevDiagResult请求，每次间隔3秒"""
                            start_time = time.time()
                            diag_request_count = 0
                            current_session_tag = session_tag  # 使用局部变量
                            
                            while time.time() - start_time < 130:  # 总共运行130秒
                                diag_request_count += 1
                                logger.info(f"{thread_username} - GetNetTransDevDiagResult 第{diag_request_count}次请求")
                                
                                # 发送请求
                                response = auth.session.post(
                                    url,
                                    json=request_data,
                                    headers=headers,
                                    timeout=10
                                )
                                
                                if response.status_code == 200:
                                    logger.info(f"  请求URL: {url}")
                                    logger.info(f"  请求数据: {request_data}")
                                    logger.info(f"  响应状态码: {response.status_code}")
                                    logger.info(f"  返回数据: {response.text}")
                                else:
                                    logger.error(f"{thread_username} - {api_name} 响应状态码: {response.status_code}")
                                    logger.error(f"{thread_username} - {api_name} 返回数据: {response.text}")
                                
                                # 更新sessionTag
                                try:
                                    response_json = response.json()
                                    if isinstance(response_json, dict) and response_json.get('status') == 200:
                                        new_data = response_json.get('data', {})
                                        new_session_tag = new_data.get('sessionTag')
                                        if new_session_tag and new_session_tag != current_session_tag:
                                            current_session_tag = new_session_tag
                                            headers['sessionTag'] = new_session_tag
                                            logger.info(f"{thread_username} - 更新sessionTag: {new_session_tag[:16]}...")
                                except:
                                    pass
                                
                                # 每次请求后等待3秒，除非已经达到130秒
                                if time.time() - start_time < 127:  # 留出3秒余量
                                    time.sleep(3)
                                else:
                                    break
                            
                            logger.info(f"{thread_username} - GetNetTransDevDiagResult 循环发送完成，共发送{diag_request_count}次请求")
                            return current_session_tag
                        
                        # 执行闭包函数并更新session_tag
                        session_tag = diag_loop()
                        continue  # 跳过下面的普通请求处理
                    
                    # 其他API的正常请求处理
                    # 使用session对象发送请求
                    response = auth.session.post(
                        url,
                        json=request_data,
                        headers=headers,
                        timeout=10
                    )

                    if response.status_code == 200:
                        if "GetNetTransDevDiagResult".lower() in url.lower():
                            logger.info(f"  请求URL: {url}")
                            logger.info(f"  请求数据: {request_data}")
                            logger.info(f"  响应状态码: {response.status_code}")
                            logger.info(f"  返回数据: {response.text}")

                        if "StartNetTransDevDiag".lower() in url.lower():
                            logger.info(f"  请求URL: {url}")
                            logger.info(f"  请求数据: {request_data}")
                            logger.info(f"  响应状态码: {response.status_code}")
                            logger.info(f"  返回数据: {response.text}")
                        else:
                            # 其他API正常处理，不打印详细信息
                            pass
                    else:
                        logger.error(f"{thread_username} - {api_name} 响应状态码: {response.status_code}")
                        logger.error(f"{thread_username} - {api_name} 返回数据: {response.text}")
                        # 记录非200响应的URL
                        with thread_lock:
                            active_threads[thread_username]['non_200_urls'].append({
                                'url': url,
                                'api_name': api_name,
                                'status_code': response.status_code,
                                'response': response.text[:200]  # 只记录前200个字符
                            })

                    # 更新sessionTag
                    try:
                        response_json = response.json()
                        if isinstance(response_json, dict) and response_json.get('status') == 200:
                            new_data = response_json.get('data', {})
                            new_session_tag = new_data.get('sessionTag')
                            if new_session_tag and new_session_tag != session_tag:
                                session_tag = new_session_tag
                                headers['sessionTag'] = session_tag
                                logger.info(f"{thread_username} - 更新sessionTag: {session_tag[:16]}...")
                    except:
                        pass
                        
                except Exception as e:
                    api_name = url.split('/')[-1]
                    logger.error(f"{thread_username} - 请求 {api_name} 出错: {e}")
                    
                    with thread_lock:
                        active_threads[thread_username]['error_count'] += 1
            
            # GET请求
            for config in request_configs_get:
                try:
                    url = config["url"]
                    api_name = url.split('/')[-1]
                    
                    response = auth.session.get(
                        url, 
                        headers=headers, 
                        timeout=10
                    )

                    if response.status_code == 200:
                        #logger.info(f"{thread_username} - {api_name} 响应状态码: {response.status_code}")
                        #logger.info(f"{thread_username} - {api_name} 请求成功")
                        pass
                    else:
                        logger.error(f"{thread_username} - {api_name} 响应状态码: {response.status_code}")
                        logger.error(f"{thread_username} - {api_name} 返回数据: {response.text}")
                        # 记录非200响应的URL
                        with thread_lock:
                            active_threads[thread_username]['non_200_urls'].append({
                                'url': url,
                                'api_name': api_name,
                                'status_code': response.status_code,
                                'response': response.text[:200]  # 只记录前200个字符
                            })

                    # 更新sessionTag
                    try:
                        response_json = response.json()
                        if isinstance(response_json, dict) and response_json.get('status') == 200:
                            new_data = response_json.get('data', {})
                            new_session_tag = new_data.get('sessionTag')
                            if new_session_tag and new_session_tag != session_tag:
                                session_tag = new_session_tag
                                headers['sessionTag'] = session_tag
                                logger.info(f"{thread_username} - 更新sessionTag: {session_tag[:16]}...")
                    except:
                        pass
                        
                except Exception as e:
                    api_name = url.split('/')[-1]
                    logger.error(f"{thread_username} - 请求 {api_name} 出错: {e}")
                    
                    with thread_lock:
                        active_threads[thread_username]['error_count'] += 1

            logger.info(f"{thread_username} - 第{request_count}/{max_rounds}轮请求完成")
            
            if request_count < max_rounds:
                time.sleep(2)  # 每轮循环间隔2秒
                
    except Exception as e:
        logger.error(f"{thread_username} 线程出错: {e}")
        
        with thread_lock:
            active_threads[thread_username]['status'] = 'error'
            active_threads[thread_username]['error_message'] = str(e)
    finally:
        with thread_lock:
            active_threads[thread_username]['status'] = 'stopped'
            active_threads[thread_username]['end_time'] = datetime.now()
        logger.info(f"{thread_username} 线程结束")
def ping_host(ip, timeout=2):
    """
    检测主机是否可达（使用ping命令）
    
    Args:
        ip: 要检测的IP地址
        timeout: 超时时间（秒）
    
    Returns:
        bool: True表示可达，False表示不可达
    """
    try:
        # Windows ping命令
        result = subprocess.run(
            ['ping', '-n', '1', '-w', str(timeout * 1000), ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout + 1
        )
        # 检查ping命令返回码，0表示成功
        return result.returncode == 0
    except Exception as e:
        #logger.warning(f"Ping检测 {ip} 失败: {e}")
        return False

def check_port(ip, port=80, timeout=2):
    """
    检测主机端口是否开放（备用方法）
    
    Args:
        ip: 要检测的IP地址
        port: 端口号
        timeout: 超时时间（秒）
    
    Returns:
        bool: True表示端口开放，False表示端口关闭
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception as e:
        logger.warning(f"端口检测 {ip}:{port} 失败: {e}")
        return False

def check_ip_connectivity(ip, timeout=2):
    """
    综合检测IP是否可达（优先ping，失败则尝试检测端口）
    
    Args:
        ip: 要检测的IP地址
        timeout: 超时时间（秒）
    
    Returns:
        bool: True表示可达，False表示不可达
    """
    # 优先使用ping检测
    if ping_host(ip, timeout):
        return True
    
    # ping失败则尝试检测80端口
    return check_port(ip, 80, timeout)

def load_config(config_file='config.json'):
    """从JSON文件加载配置"""
    try:
        if not os.path.exists(config_file):
            logger.error(f"配置文件 {config_file} 不存在")
            return None
            
        with open(config_file, 'r', encoding='utf-8') as f:
            config = json.load(f)
            
        logger.info(f"成功加载配置文件: {config_file}")
        logger.info(f"发现 {len(config.get('switches', []))} 个交换机配置")
        return config
        
    except Exception as e:
        logger.error(f"加载配置文件失败: {e}")
        return None

def print_final_report():
    """打印最终运行报告，重点显示失败的线程和非200响应"""
    with thread_lock:
        if not active_threads:
            logger.info("没有线程运行记录")
            return
        
        logger.info("=" * 80)
        logger.info("最终运行报告")
        logger.info("=" * 80)
        
        total_threads = len(active_threads)
        stopped_threads = sum(1 for info in active_threads.values() if info.get('status') == 'stopped')
        error_threads = sum(1 for info in active_threads.values() if info.get('status') == 'error')
        running_threads = sum(1 for info in active_threads.values() if info.get('status') == 'running')
        
        logger.info(f"总线程数: {total_threads}")
        logger.info(f"正常运行完成: {stopped_threads}")
        logger.info(f"运行中: {running_threads}")
        logger.info(f"运行失败: {error_threads}")
        logger.info("")
        
        # 显示成功登录的IP、用户名和密码
        logger.info("=" * 80)
        logger.info("成功登录信息:")
        logger.info("=" * 80)
        
        has_successful_login = False
        for username, info in active_threads.items():
            if info.get('status') == 'stopped' and info.get('successful_password'):
                has_successful_login = True
                ip = info.get('ip', 'unknown')
                original_username = info.get('original_username', 'unknown')
                successful_password = info.get('successful_password', 'unknown')
                
                logger.info(f"IP: {ip}")
                logger.info(f"用户名: {original_username}")
                logger.info(f"密码: {successful_password}")
                logger.info("-" * 40)
        
        if not has_successful_login:
            logger.info("没有成功登录的记录")
        
        logger.info("")
        
        # 显示失败的线程详情
        if error_threads > 0:
            logger.info("=" * 80)
            logger.info("失败线程详情:")
            logger.info("=" * 80)
            
            for username, info in active_threads.items():
                if info.get('status') == 'error':
                    error_message = info.get('error_message', '未知错误')
                    ip = info.get('ip', 'unknown')
                    request_count = info.get('request_count', 0)
                    error_count = info.get('error_count', 0)
                    
                    logger.error(f"线程: {username}")
                    logger.error(f"  IP: {ip}")
                    logger.error(f"  错误信息: {error_message}")
                    logger.error(f"  请求次数: {request_count}")
                    logger.error(f"  错误次数: {error_count}")
                    logger.error("-" * 40)
        else:
            logger.info("✓ 所有线程运行正常，没有失败记录")
        
        # 显示非200响应的URL
        logger.info("")
        logger.info("=" * 80)
        logger.info("非200响应URL详情:")
        logger.info("=" * 80)
        
        has_non_200 = False
        for username, info in active_threads.items():
            non_200_urls = info.get('non_200_urls', [])
            if non_200_urls:
                has_non_200 = True
                ip = info.get('ip', 'unknown')
                status = info.get('status', 'unknown')
                
                logger.error(f"线程: {username} (IP: {ip}, 状态: {status})")
                for url_info in non_200_urls:
                    logger.error(f"  URL: {url_info['url']}")
                    logger.error(f"  API: {url_info['api_name']}")
                    logger.error(f"  状态码: {url_info['status_code']}")
                    logger.error(f"  响应: {url_info['response']}")
                    logger.error("  " + "-" * 40)
                logger.error("")
        
        if not has_non_200:
            logger.info("✓ 所有URL响应正常，没有非200响应")
        
        logger.info("=" * 80)

def parse_arguments():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description='多线程会话测试工具')
    parser.add_argument('-c', '--config', default='config.json', help='配置文件路径 (默认: config.json)')
    parser.add_argument('-t', '--threads', type=int, help='每个交换机的线程数 (覆盖配置文件)')
    parser.add_argument('-r', '--rounds', type=int, help='请求轮数 (覆盖配置文件)')
    
    return parser.parse_args()

def main():
    """主函数 - 从配置文件读取多个交换机配置"""
    # 解析命令行参数
    args = parse_arguments()
    
    # 加载配置文件
    config = load_config(args.config)
    if not config:
        logger.error("无法加载配置文件，程序退出")
        return
    
    # 获取全局池子
    global_ip_pool = config.get('ip_pool', [])
    global_username_pool = config.get('username_pool', [])
    global_password_pool = config.get('password_pool', [])
    
    if global_ip_pool:
        logger.info(f"使用全局IP池，包含 {len(global_ip_pool)} 个IP")
    if global_username_pool:
        logger.info(f"使用全局用户名池，包含 {len(global_username_pool)} 个用户名")
    if global_password_pool:
        logger.info(f"使用全局密码池，包含 {len(global_password_pool)} 个密码")
    
    # 获取交换机配置（如果存在）
    switches = config.get('switches', [])
    
    # 如果没有switches配置，使用全局池子生成
    if not switches and global_ip_pool and global_username_pool:
        logger.info("未发现switches配置，使用全局池子生成交换机列表")
        for ip in global_ip_pool:
            for username in global_username_pool:
                switches.append({
                    "ip": ip,
                    "username": username,
                    "description": f"Auto-generated: {ip}"
                })
    
    if not switches:
        logger.error("配置文件中没有交换机配置，且无法从全局池子生成")
        return
    
    # 对IP池进行连通性检测
    if global_ip_pool:
        logger.info("开始检测IP池中各IP的连通性...")
        reachable_ips = []
        unreachable_ips = []
        
        for ip in global_ip_pool:
            if check_ip_connectivity(ip, timeout=2):
                reachable_ips.append(ip)
                logger.info(f"  ✓ {ip} 可达")
            else:
                unreachable_ips.append(ip)
                logger.warning(f"  ✗ {ip} 不可达，将跳过")
        
        logger.info(f"IP连通性检测完成: {len(reachable_ips)} 个可用, {len(unreachable_ips)} 个不可达")
        
        if unreachable_ips:
            logger.info(f"不可达IP列表: {', '.join(unreachable_ips)}")
        
        # 过滤掉不可达的IP
        if reachable_ips:
            # 更新switches配置，只保留可达的IP
            original_count = len(switches)
            switches = [s for s in switches if s.get('ip') in reachable_ips]
            filtered_count = len(switches)
            logger.info(f"已过滤 {original_count - filtered_count} 个不可达交换机配置")
        else:
            logger.error("没有可用的IP，程序退出")
            return
    
    # 获取线程数和请求轮数（命令行参数优先）
    threads_per_switch = args.threads if args.threads else config.get('threads_per_switch', 1)
    request_rounds = args.rounds if args.rounds else config.get('request_rounds', 2)
    
    logger.info(f"程序启动 - 交换机数量: {len(switches)}, 每个交换机线程数: {threads_per_switch}, 请求轮数: {request_rounds}")
    
    threads = []
    thread_counter = 0
    
    # 为每个交换机创建线程
    for switch in switches:
        ip = switch.get('ip')
        username = switch.get('username')
        description = switch.get('description', ip)
        base_url = f"http://{ip}"
        
        # 获取密码列表（优先级：交换机独立密码 > 全局密码池）
        passwords = switch.get('passwords')
        if passwords is None:
            # 检查是否有单个password字段（向后兼容）
            password = switch.get('password')
            if password:
                passwords = [password]
            elif global_password_pool:
                # 使用全局密码池
                passwords = global_password_pool
            else:
                logger.error(f"交换机 {description} ({ip}) 没有配置密码，且没有全局密码池")
                continue
        
        logger.info(f"开始处理交换机: {description} ({ip}), 密码数量: {len(passwords)}")
        
        # 为当前交换机创建多个线程
        for i in range(1, threads_per_switch + 1):
            thread_counter += 1
            
            # 生成唯一的线程用户名（包含IP和线程号）
            thread_username = f"{username}_{ip.replace('.', '_')}_{i}"
            
            thread = threading.Thread(
                target=user_worker,
                args=(thread_counter, thread_username, passwords, base_url, username, request_rounds)
            )
            thread.daemon = True
            thread.start()
            threads.append(thread)
            
            logger.info(f"创建线程 {thread_counter} - 交换机: {description}, 用户名: {thread_username}")
            time.sleep(0.5)  # 稍微延迟，避免同时登录压力过大
    
    logger.info(f"所有线程已启动 - 总计 {len(threads)} 个线程，持续运行中...")
    
    # 定期打印线程状态
    status_counter = 0
    try:
        while True:
            time.sleep(10)  # 每10秒检查一次
            status_counter += 1
            
            # 简单状态报告
            with thread_lock:
                running_count = sum(1 for info in active_threads.values() if info.get('status') == 'running')
                error_count = sum(1 for info in active_threads.values() if info.get('status') == 'error')
                stopped_count = sum(1 for info in active_threads.values() if info.get('status') == 'stopped')
            
            logger.info(f"状态检查 - 运行中: {running_count}, 已完成: {stopped_count}, 错误: {error_count}, 总计: {len(active_threads)}")
            
            # 检查所有线程是否都已完成（stopped或error状态）
            if running_count == 0:
                logger.info("所有线程已完成，程序即将退出...")
                break
        
        # 打印最终报告并退出
        print_final_report()
        logger.info("程序正常退出")
                
    except KeyboardInterrupt:
        logger.info("收到中断信号，程序正在退出...")
        print_final_report()
    except Exception as e:
        logger.error(f"主线程出错: {e}")
        print_final_report()
if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.error(f"程序运行出错: {e}")
        print_final_report()
