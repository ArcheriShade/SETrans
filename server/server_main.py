import os
import re
import sys
import time
import json
import logging
from socketserver import BaseRequestHandler, ThreadingTCPServer

import pymysql
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

from flag import *

SERVER_ADDR = ("10.10.10.1", 7777)      # 服务器地址
CHUNK_SIZE = 1024                       # 传输数据块大小
DB_HOST = "10.10.10.1"                  # 数据库地址
DB_PORT = 3306                          # 数据库端口
DB_USER = "root"                        # 数据库用户
DB_PASSWORD = "toor"                    # 数据库密码
DB_DATABASE = "SETrans"                 # 数据库名称
DB_CHARSET = "utf8mb4"                  # 数据库编码集


class ClientHandler(BaseRequestHandler):
    def handle(self):
        global db_handler
        # 每个client的连接句柄、会话密钥、数据库游标以及日志句柄
        self.c_socket = self.request
        self.sess_key = get_random_bytes(16)
        self.db_cur = db_handler.cursor()
        self.logger = None
        # 待传输数据信息
        self.file_name = ""
        self.enc_data = b''
        self.enc_data_len = 0
        # 用户信息
        self.username = ""
        self.usertype = ""

        # 初始化日志句柄
        self.loggerInit()
        # 建立安全信道
        if self.seSessInit() == 0:
            # 接收命令
            self.recvCmd()

        self.c_socket.close()

    def loggerInit(self):
        """
        对每一个client创建一个logger
        """
        c_ip = self.client_address[0]
        c_port = self.client_address[1]
        self.logger = logging.getLogger(f"{c_ip}_{c_port}")
        self.logger.setLevel(logging.INFO)
        fh = logging.FileHandler(f"./log/{c_ip}_{c_port}", mode='a', encoding='utf-8')
        fh.setLevel(logging.INFO)
        fmt = logging.Formatter("%(asctime)s|%(levelname)s|%(message)s")
        fh.setFormatter(fmt)
        self.logger.addHandler(fh)

    def seSessInit(self):
        """
        初始化安全信道
        """
        self.logger.info("TCP连接成功")
        # 生成会话密钥的摘要
        digest = SHA256.new(self.sess_key)

        # 用client-公钥对会话密钥进行加密
        with open("./keys/c_public.pem", 'rb') as file_obj:
            c_pub_key = RSA.import_key(file_obj.read())
        en_sess_key = PKCS1_OAEP.new(c_pub_key).encrypt(self.sess_key)

        # 用server-私钥对摘要进行签名
        with open("./keys/s_private.pem", 'rb') as file_obj:
            s_pri_key = RSA.import_key(file_obj.read())
        signature = pkcs1_15.new(s_pri_key).sign(digest)

        # 将加密后的会话密钥和签名发送给client
        data = CONN_KEYSEND + en_sess_key + signature
        self.c_socket.send(data)
        self.logger.info("会话密钥已发送")

        # 获取client响应
        code = self.c_socket.recv(CHUNK_SIZE)
        if code != CONN_KEYRECV:
            self.c_socket.close()
            return -1

        self.logger.info("安全信道初始化完成")
        return 0

    def recvCmd(self):
        """
        监听命令报文
        """
        while True:
            cipher_data = self.c_socket.recv(CHUNK_SIZE)
            data = self.decryptData(cipher_data)
            if data == -1:
                self.sendError()
                return -1
            code = data[0].to_bytes(1, 'big')
            self.logger.info(f"收到信号：{hex(int.from_bytes(code, 'big'))}")

            # 用户注册
            if code == ACON_SIGN:
                username, password = self.aconInputCheck(data[1:])
                if len(username) > 0 and len(password) > 0:
                    if self.signUp(username, password) < 0:
                        cipher_data = self.encryptData(ACON_NEXIS)
                        self.c_socket.send(cipher_data)
                        self.logger.warning(f"用户注册：用户名 ’{username}‘ 已存在")
                    else:
                        cipher_data = self.encryptData(ACON_OK)
                        self.c_socket.send(cipher_data)
                        self.logger.info(f"用户注册：用户 ’{username}‘ 注册成功")
                else:
                    cipher_data = self.encryptData(ACON_FMATERR)
                    self.c_socket.send(cipher_data)
                    self.logger.warning("用户注册：用户输入格式错误")

            # 用户登录
            elif code == ACON_LOGIN:
                username, password = self.aconInputCheck(data[1:])
                if len(username) > 0 and len(password) > 0:
                    if self.login(username, password) < 0:
                        cipher_data = self.encryptData(ACON_NPERR)
                        self.c_socket.send(cipher_data)
                        self.logger.warning("用户登录：用户名或密码错误")
                    else:
                        cipher_data = self.encryptData(ACON_OK)
                        self.c_socket.send(cipher_data)
                        self.logger.info(f"用户登录：用户 ’{username}‘ 登录成功")
                else:
                    cipher_data = self.encryptData(ACON_FMATERR)
                    self.c_socket.send(cipher_data)
                    self.logger.warning("用户登录：用户输入格式错误")

            # 获取文件列表
            elif code == FILE_LS:
                files = os.listdir("./filehub")
                files_info = []
                for file in files:
                    files_info.append((file, os.stat(f"./filehub/{file}").st_size))
                ls_data = FILE_TRANS + json.dumps(files_info).encode()
                # 加密列表信息
                self.enc_data = self.encryptData(ls_data)
                # 发送加密列表信息的长度
                self.enc_data_len = len(self.enc_data)
                len_data = FILE_LEN + self.enc_data_len.to_bytes(4, 'big')
                cipher_len_data = self.encryptData(len_data)
                self.c_socket.send(cipher_len_data)
                self.logger.info("文件列表：发送加密的文件列表数据长度")

            # 获取文件
            elif code == FILE_GET:
                files = os.listdir("./filehub")
                file = data[1:].decode()
                self.file_name = file
                self.logger.info(f"文件获取：目标文件 ’{file}‘")
                if file not in files:
                    cipher_data = self.encryptData(FILE_NEXIS)
                    self.c_socket.send(cipher_data)
                    self.logger.warning("文件获取：目标文件不存在")
                else:
                    with open(f"./filehub/{file}", 'rb') as file_obj:
                        file_data = FILE_TRANS + file_obj.read()
                    # 加密文件
                    self.enc_data = self.encryptData(file_data)
                    # 发送加密文件的长度
                    self.enc_data_len = len(self.enc_data)
                    len_data = FILE_LEN + self.enc_data_len.to_bytes(4, 'big')
                    cipher_len_data = self.encryptData(len_data)
                    self.c_socket.send(cipher_len_data)
                    self.logger.info("文件获取：发送加密的文件数据长度")

            # 收到确认接受，发送客户端所需数据
            elif code == FILE_RECV:
                totalsent = 0
                start_time = time.time()
                while totalsent < self.enc_data_len:
                    edge = min(CHUNK_SIZE, self.enc_data_len - totalsent)
                    data = self.enc_data[totalsent:totalsent+edge]
                    sent = self.c_socket.send(data)
                    totalsent += sent
                    if self.usertype != "VIP":
                        # 价值10万的代码
                        time.sleep(0.01)
                end_time = time.time()
                msg = f"数据传输：传输文件‘{self.file_name}’，用户‘{self.username}’，用户类型‘{self.usertype}’，用时{end_time - start_time}."
                self.logger.info(msg)

    def encryptData(self, data):
        """
        对数据进行可校验加密
        """
        cipher = AES.new(self.sess_key, AES.MODE_EAX)
        enc_data, tag = cipher.encrypt_and_digest(data)
        cipher_data = cipher.nonce + tag + enc_data
        return cipher_data

    def decryptData(self, cipher_data):
        """
        对加密数据进行长度判断、解密并校验
        """
        # 判断长度
        cipher_data_len = len(cipher_data)
        if cipher_data_len < 33:
            return -1

        # 解密并校验
        nonce, tag, enc_data = cipher_data[:16], cipher_data[16:32], cipher_data[32:]
        cipher = AES.new(self.sess_key, AES.MODE_EAX, nonce)
        try:
            data = cipher.decrypt_and_verify(enc_data, tag)
        except ValueError as e:
            return -1

        return data

    def sendError(self):
        """
        发生错误，告知关闭连接
        """
        cipher_data = self.encryptData(CONN_CLOSE)
        self.c_socket.send(cipher_data)
        self.logger.critical("发生错误，关闭连接")
        return -1

    def aconInputCheck(self, acon_input):
        """
        检查用户名与密码输入
        """
        data = acon_input.decode().split("/")
        if len(data) != 2:
            self.logger.warning("账户操作：用户输入字段数量异常")
            return "", ""
        else:
            name, psw = data[0], data[1]
            name_check = re.match(r"^[a-zA-Z0-9_-]{4,16}$", name)
            psw_check = re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,16}$", psw)
            if name_check and psw_check:
                self.logger.info("账户操作：用户输入字段正常")
                return name, psw
            else:
                self.logger.warning("账户操作：用户输入字段异常")
                self.logger.warning(f"账户操作：用户输入 ’{name}/{psw}‘")
                return "", ""

    def signUp(self, name, psw):
        """
        将用户名和密码写入数据库，密码加盐存储，预编译执行SQL
        """
        global db_handler
        # 判断用户是否存在
        sql = "SELECT * FROM user WHERE username=%s;"
        if self.db_cur.execute(sql, (name)):
            return -1
        else:
            salt = get_random_bytes(64)
            with open("./keys/saltlist", 'a') as file_obj:
                file_obj.write(name + ":" + salt.hex() + "\n")
            psw_hash = SHA256.new(psw.encode() + salt).hexdigest()
            sql = "INSERT INTO user(username, usertype, password) VALUES(%s, %s, %s);"
            self.db_cur.execute(sql, (name, "normal", psw_hash))
            db_handler.commit()
            return 0

    def login(self, name, psw):
        """
        用户登录，取对应盐值计算密码hash，预编译执行SQL
        """
        global db_handler
        # 获取用户的盐值
        salt = b""
        with open("./keys/saltlist", 'r') as file_obj:
            line = file_obj.readline()
            while line:
                if not line.startswith(name + ":"):
                    line = file_obj.readline()
                    continue
                else:
                    salt = bytes.fromhex(line.split(":")[1].strip())
                    break

        # 尝试匹配
        psw_hash = SHA256.new(psw.encode() + salt).hexdigest()
        sql = "SELECT * FROM user WHERE username=%s and password=%s;"
        if self.db_cur.execute(sql, (name, psw_hash)):
            self.username = name
            sql = "SELECT usertype FROM user WHERE username=%s;"
            self.db_cur.execute(sql, (name))
            self.usertype = self.db_cur.fetchone()[0]
            return 0
        else:
            return -1


if __name__ == "__main__":
    # 建立服务器连接句柄及操作游标
    db_handler = pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_DATABASE,
        charset=DB_CHARSET
    )

    # server对每一个client建立TCP连接
    server = ThreadingTCPServer(SERVER_ADDR, ClientHandler)
    server.serve_forever()
