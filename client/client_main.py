import sys
from socket import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

from PySide6.QtWidgets import QApplication, QWidget
from ui_login import Ui_Login

from flag import *

SERVER_ADDR = ("10.10.10.1", 7777)  # 服务器地址
CHUNK_SIZE = 1024                   # 传输数据大小


class CLoginWidget(QWidget):
    def __init__(self):
        global c_socket
        global sess_key
        super().__init__()
        self.ui = Ui_Login()
        self.ui.setupUi(self)

        # 绑定button函数
        self.ui.button_signup.clicked.connect(self.signUp)
        self.ui.button_login.clicked.connect(self.login)

        # 建立安全信道
        self.seSessInit()

    def seSessInit(self):
        """
        初始化安全信道
        """
        global c_socket
        global sess_key

        # 建立TCP连接
        c_socket = socket(AF_INET, SOCK_STREAM)
        c_socket.connect(SERVER_ADDR)

        # 接收server发来的数据
        data = c_socket.recv(CHUNK_SIZE)
        code, en_sess_key, signature = data[:1], data[1:257], data[257:]

        if code != CONN_KEYSEND:
            self.ui.text_browser.setText("Failed to establish a secure channel.")
            c_socket.send(CONN_CLOSE)
            c_socket.close()
            return -1

        # 用client-私钥解密获得会话密钥
        with open("./keys/c_private.pem", 'rb') as file_obj:
            c_pri_key = RSA.import_key(file_obj.read())
        sess_key = PKCS1_OAEP.new(c_pri_key).decrypt(en_sess_key)

        # 用server-公钥验签
        digest = SHA256.new(sess_key)
        with open("./keys/s_public.pem", 'rb') as file_obj:
            s_pub_key = RSA.import_key(file_obj.read())
        # 验签成功返回None，否则抛出ValueError: Invalid signature
        try:
            pkcs1_15.new(s_pub_key).verify(digest, signature)
        except ValueError as e:
            self.ui.text_browser.setText("Failed to establish a secure channel.")
            c_socket.send(CONN_CLOSE)
            c_socket.close()
            return -1
        else:
            c_socket.send(CONN_KEYRECV)
            self.ui.text_browser.setText("Security channel setup completed.")
            return 0

    def signUp(self):
        """
        用户注册
        """
        global c_socket
        global sess_key

        # 只进行简单的非空校验
        username = self.ui.editline_user.text().strip()
        password = self.ui.editline_pwd.text().strip()
        if len(username) == 0 or len(password) == 0:
            info = "Username or password cannot be empty."
            return -1

        # 加密数据并发送
        data = ACON_SIGN + f"{username}/{password}".encode()
        cipher_data = self.encryptData(data)
        c_socket.send(cipher_data)


        ################################


        self.ui.text_browser.setText(info)
        self.ui.editline_pwd.clear()

    def login(self):
        pass

    def encryptData(self, data):
        """
        对数据进行可校验加密
        """
        global c_socket
        global sess_key
        cipher = AES.new(sess_key, AES.MODE_EAX)
        enc_data, tag = cipher.encrypt_and_digest(data)
        cipher_data = cipher.nonce + tag + enc_data
        return cipher_data

    # def recvData(self):
    #     """
    #     接收数据
    #     """
    #     data = c_socket.recv(CHUNK_SIZE)
    #     return data
    #
    # def testCode(self, data):
    #     code = data[0].to_bytes(1, 'big')
    #     if code == ACON_LOGIN:
    #         self.ui.text_browser.setText("Login OK!")
    #     else:
    #         self.ui.text_browser.setText("Oops!")
    #     c_socket.close()


if __name__ == '__main__':
    app = QApplication(sys.argv)

    # TCP连接句柄与会话密钥
    c_socket = None
    sess_key = b''

    login_window = CLoginWidget()
    login_window.show()

    app.exec()

    c_socket.close()
    sys.exit()
