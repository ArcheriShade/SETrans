import sys
from socket import *
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

from flag import *

SERVER_ADDR = ("10.10.10.1", 7777)      # 服务器地址
CHUNK_SIZE = 1024                       # 传输数据块大小


def clientHandler():
    pass


def seSessInit():
    """
    初始化安全信道
    """
    global c_socket
    global sess_key

    # 生成会话密钥的摘要
    digest = SHA256.new(sess_key)

    # 用client-公钥对会话密钥进行加密
    with open("./keys/c_public.pem", 'rb') as file_obj:
        c_pub_key = RSA.import_key(file_obj.read())
    en_sess_key = PKCS1_OAEP.new(c_pub_key).encrypt(sess_key)

    # 用server-私钥对摘要进行签名
    with open("./keys/s_private.pem", 'rb') as file_obj:
        s_pri_key = RSA.import_key(file_obj.read())
    signature = pkcs1_15.new(s_pri_key).sign(digest)

    # 将加密后的会话密钥和签名发送给client
    data = CONN_KEYSEND + en_sess_key + signature
    c_socket.send(data)

    # 获取client响应
    code = c_socket.recv(CHUNK_SIZE)
    if code != CONN_KEYRECV:
        c_socket.close()
        s_socket.close()
        return -1

    return 0


def recvCmd():
    """
    接收加密命令并解密解析
    """
    global c_socket
    global sess_key



if __name__ == "__main__":
    # 服务器-客户 建立TCP连接
    s_socket = socket(AF_INET, SOCK_STREAM)
    s_socket.bind(SERVER_ADDR)
    s_socket.listen(10)
    c_socket, c_info = s_socket.accept()

    # 生成会话密钥
    sess_key = get_random_bytes(16)
    print(sess_key)

    # 建立安全信道
    if seSessInit() == 0:
        # recvCmd()
        print(sess_key)

    c_socket.close()
    s_socket.close()
