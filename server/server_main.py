import sys
from socket import *

from flag import *

SERVER_ADDR = ("10.10.10.1", 7777)      # 服务器地址
CHUNK_SIZE = 1024                       # 传输数据块大小


def sessKeyInit():
    """
    初始化会话密钥
    """
    global c_socket
    data = ACON_LOGIN
    c_socket.send(data)


if __name__ == "__main__":
    # 建立TCP连接
    s_socket = socket(AF_INET, SOCK_STREAM)
    s_socket.bind(SERVER_ADDR)
    s_socket.listen(5)
    c_socket, c_info = s_socket.accept()

    sessKeyInit()

    c_socket.close()
    s_socket.close()
