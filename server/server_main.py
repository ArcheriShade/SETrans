import sys
from socketserver import BaseRequestHandler, ThreadingTCPServer
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

from flag import *

SERVER_ADDR = ("10.10.10.1", 7777)      # 服务器地址
CHUNK_SIZE = 1024                       # 传输数据块大小


class ClientHandler(BaseRequestHandler):
    def handle(self):
        # 每个client的连接句柄以及会话密钥
        self.c_socket = self.request
        self.sess_key = get_random_bytes(16)
        # 建立安全信道
        if self.seSessInit() == 0:
            # 接收命令
            self.recvCmd()

        self.c_socket.close()

    def seSessInit(self):
        """
        初始化安全信道
        """
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

        # 获取client响应
        code = self.c_socket.recv(CHUNK_SIZE)
        if code != CONN_KEYRECV:
            self.c_socket.close()
            return -1

        return 0

    def recvCmd(self):
        """
        监听命令报文
        """
        while True:
            cipher_data = self.c_socket.recv(CHUNK_SIZE)
            cipher_data_len = len(cipher_data)
            if cipher_data_len < 33:
                self.sendError()
                return -1

            data = self.decryptData(cipher_data)
            code = data[0]

            ##############################

    def encryptData(self, data):
        """
        对数据进行可校验加密
        """
        cipher = AES.new(sess_key, AES.MODE_EAX)
        enc_data, tag = cipher.encrypt_and_digest(data)
        cipher_data = cipher.nonce + tag + enc_data
        return cipher_data

    def decryptData(self, cipher_data):
        """
        对加密数据进行解密并校验
        """
        nonce, tag, enc_data = cipher_data[:16], cipher_data[16:32], cipher_data[32:]
        cipher = AES.new(self.sess_key, AES.MODE_EAX, nonce)
        data = cipher.decrypt_and_verify(enc_data, tag)
        return data

    def sendError(self):
        """
        发生错误，告知关闭连接
        """
        cipher_data = self.encryptData(CONN_CLOSE)
        self.c_socket.send(cipher_data)
        return -1


if __name__ == "__main__":
    # server对每一个client建立TCP连接
    server = ThreadingTCPServer(SERVER_ADDR, ClientHandler)
    server.serve_forever()
