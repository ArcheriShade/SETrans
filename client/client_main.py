import sys
import json
import shutil
from socket import *

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

from PySide6.QtWidgets import QApplication, QWidget, QAbstractItemView
from PySide6.QtCore import QStringListModel
from ui_login import Ui_Login
from ui_setrans import Ui_SETrans

from flag import *

SERVER_ADDR = ("10.10.10.1", 7777)  # 服务器地址
CHUNK_SIZE = 1024                   # 传输数据大小


class CLoginWidget(QWidget):
    def __init__(self, main_ui):
        global c_socket
        global sess_key
        super().__init__()
        self.ui = Ui_Login()
        self.ui.setupUi(self)
        self.main_ui = main_ui

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
            c_socket.send(CONN_CLOSE)
            self.ui.text_browser.setText("Failed to establish a secure channel.")
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
        # 只进行简单的非空校验
        username = self.ui.editline_user.text().strip()
        password = self.ui.editline_pwd.text().strip()
        if len(username) == 0 or len(password) == 0:
            self.ui.text_browser.setText("Username or password cannot be empty.")
            return -1

        # 加密数据并发送
        data = ACON_SIGN + f"{username}/{password}".encode()
        cipher_data = self.encryptData(data)
        c_socket.send(cipher_data)

        # 接收服务端响应
        cipher_data = c_socket.recv(CHUNK_SIZE)
        data = self.decryptData(cipher_data)
        if data == -1:
            self.sessBroken()
            return -1
        code = data[0].to_bytes(1, 'big')
        if code == ACON_OK:
            self.ui.text_browser.setText("Registration succeeded.")
            self.ui.editline_pwd.clear()
            return 0
        elif code == ACON_FMATERR:
            self.ui.text_browser.setText("Username or password format error.")
            self.ui.editline_pwd.clear()
            return -1
        elif code == ACON_NEXIS:
            self.ui.text_browser.setText("Username already exists.")
            self.ui.editline_pwd.clear()
            return -1
        else:
            self.ui.text_browser.setText("Registration failed.")
            self.ui.editline_pwd.clear()
            return -1

    def login(self):
        """
        用户登录
        """
        global c_socket
        # 只进行简单的非空校验
        username = self.ui.editline_user.text().strip()
        password = self.ui.editline_pwd.text().strip()
        if len(username) == 0 or len(password) == 0:
            self.ui.text_browser.setText("Username or password cannot be empty.")
            return -1

        # 加密数据并发送
        data = ACON_LOGIN + f"{username}/{password}".encode()
        cipher_data = self.encryptData(data)
        c_socket.send(cipher_data)

        # 接收服务端响应
        cipher_data = c_socket.recv(CHUNK_SIZE)
        data = self.decryptData(cipher_data)
        if data == -1:
            self.sessBroken()
            return -1
        code = data[0].to_bytes(1, 'big')
        if code == ACON_OK:
            self.ui.text_browser.setText("Login succeeded.")
            self.close()
            self.main_ui.show()
            return 0
        elif code == ACON_FMATERR:
            self.ui.text_browser.setText("Username or password format error.")
            self.ui.editline_pwd.clear()
            return -1
        elif code == ACON_NPERR:
            self.ui.text_browser.setText("Username or password error.")
            self.ui.editline_pwd.clear()
            return -1
        else:
            self.ui.text_browser.setText("Login failed.")
            self.ui.editline_pwd.clear()
            return -1

    def encryptData(self, data):
        """
        对数据进行可校验加密
        """
        global sess_key
        cipher = AES.new(sess_key, AES.MODE_EAX)
        enc_data, tag = cipher.encrypt_and_digest(data)
        cipher_data = cipher.nonce + tag + enc_data
        return cipher_data

    def decryptData(self, cipher_data):
        """
        对加密数据进行长度判断、解密并校验
        """
        global sess_key
        # 判断长度
        cipher_data_len = len(cipher_data)
        if cipher_data_len < 33:
            return -1

        # 解密并校验
        nonce, tag, enc_data = cipher_data[:16], cipher_data[16:32], cipher_data[32:]
        cipher = AES.new(sess_key, AES.MODE_EAX, nonce)
        try:
            data = cipher.decrypt_and_verify(enc_data, tag)
        except ValueError as e:
            return -1

        return data

    def sessBroken(self):
        """
        安全信道破损，关闭连接
        """
        global c_socket
        global flag_broken
        c_socket.close()
        self.ui.text_browser.setText("Security channel is broken.")
        self.ui.button_login.setDisabled(True)
        self.ui.button_signup.setDisabled(True)
        flag_broken = 1


class CSETransWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.ui = Ui_SETrans()
        self.ui.setupUi(self)

        # 文件信息列表、已选择文件名称、已选择文件大小
        self.files_info = []
        self.selected = ""
        self.selected_size = 0
        self.slm = QStringListModel()

        # 绑定button函数
        self.ui.button_ls.clicked.connect(self.getList)
        self.ui.button_get.clicked.connect(self.getFile)
        self.ui.list_view.clicked.connect(self.clickList)
        # 未选择文件禁止get（前端）
        self.ui.button_get.setDisabled(True)
        # 禁止双击listView编辑
        self.ui.list_view.setEditTriggers(QAbstractItemView.NoEditTriggers)

    def getList(self):
        """
        获取文件列表
        """
        global c_socket
        # 发送获取文件列表的信号
        data = FILE_LS
        cipher_data = self.encryptData(data)
        c_socket.send(cipher_data)

        # 接收服务端响应 - 加密数据长度
        cipher_data = c_socket.recv(CHUNK_SIZE)
        data = self.decryptData(cipher_data)
        if data == -1:
            self.sessBroken()
            return -1
        code = data[0].to_bytes(1, 'big')
        if code == FILE_LEN:
            pass
        else:
            self.sessBroken()
            return -1
        length = int.from_bytes(data[1:], 'big')

        # 发送确认接收数据
        data = FILE_RECV
        cipher_data = self.encryptData(data)
        c_socket.send(cipher_data)

        # 根据数据长度，接收加密数据
        cipher_data = self.recvEncData(length)
        data = self.decryptData(cipher_data)
        code = data[0].to_bytes(1, 'big')
        if code == FILE_TRANS:
            self.files_info = json.loads(data[1:])

            # 测试超大文件
            self.files_info.append(("big file.bin", 358548297728))

            files_name = []
            for info in self.files_info:
                files_name.append(info[0])
            self.slm.setStringList(files_name)
            self.ui.list_view.setModel(self.slm)
            self.ui.text_browser.setText("Successfully obtained the file list.")
            # 未选中文件不允许get
            self.ui.button_get.setDisabled(True)
            return 0
        else:
            self.sessBroken()
            return -1

    def getFile(self):
        global c_socket
        # 发送获取文件的信号
        data = FILE_GET + self.selected.encode()
        cipher_data = self.encryptData(data)
        c_socket.send(cipher_data)

        # 接收服务端响应 - 加密文件长度
        cipher_data = c_socket.recv(CHUNK_SIZE)
        data = self.decryptData(cipher_data)
        if data == -1:
            self.sessBroken()
            return -1
        code = data[0].to_bytes(1, 'big')
        if code == FILE_LEN:
            pass
        elif code == FILE_NEXIS:
            self.ui.text_browser.setText("File does not exist.")
            return -1
        else:
            self.sessBroken()
            return -1
        length = int.from_bytes(data[1:], 'big')

        # 发送确认接收数据
        data = FILE_RECV
        cipher_data = self.encryptData(data)
        c_socket.send(cipher_data)

        # 根据数据长度，接收加密数据
        cipher_data = self.recvEncData(length)
        data = self.decryptData(cipher_data)
        code = data[0].to_bytes(1, 'big')
        if code == FILE_TRANS:
            file_data = data[1:]
            with open(f"./filehub/{self.selected}", 'wb') as file_obj:
                file_obj.write(file_data)
            self.ui.text_browser.setText(f"Successfully obtained file '{self.selected}'.")
            return 0
        else:
            self.sessBroken()
            return -1

    def clickList(self, qModelIndex):
        """
        选择文件，判断磁盘空间是否足够，相应启用/关闭get button
        """
        self.selected = self.files_info[qModelIndex.row()][0]
        self.selected_size = self.files_info[qModelIndex.row()][1]

        msg = ""
        total_b, used_b, free_b = shutil.disk_usage("./filehub")
        if len(self.selected) != 0:
            msg = f"File name: {self.selected}\n"
            msg += f"File size: {self.selected_size}\n"
            if free_b > self.selected_size:
                msg += "Sufficient disk space remaining."
                self.ui.button_get.setEnabled(True)
            else:
                msg += "Insufficient disk space remaining."
                self.ui.button_get.setDisabled(True)
        self.ui.text_browser.setText(msg)

    def recvEncData(self, length):
        """
        获取指定长度的加密数据
        """
        global c_socket
        chunks = []
        recv_size = 0
        while recv_size < length:
            chunk = c_socket.recv(min(CHUNK_SIZE, length - recv_size))
            chunks.append(chunk)
            recv_size += len(chunk)
        cipher_data = b''.join(chunks)
        return cipher_data

    def encryptData(self, data):
        """
        对数据进行可校验加密
        """
        global sess_key
        cipher = AES.new(sess_key, AES.MODE_EAX)
        enc_data, tag = cipher.encrypt_and_digest(data)
        cipher_data = cipher.nonce + tag + enc_data
        return cipher_data

    def decryptData(self, cipher_data):
        """
        对加密数据进行长度判断、解密并校验
        """
        global sess_key
        # 判断长度
        cipher_data_len = len(cipher_data)
        if cipher_data_len < 33:
            return -1

        # 解密并校验
        nonce, tag, enc_data = cipher_data[:16], cipher_data[16:32], cipher_data[32:]
        cipher = AES.new(sess_key, AES.MODE_EAX, nonce)
        try:
            data = cipher.decrypt_and_verify(enc_data, tag)
        except ValueError as e:
            return -1

        return data

    def sessBroken(self):
        """
        安全信道破损，关闭连接
        """
        global c_socket
        global flag_broken
        c_socket.close()
        self.ui.text_browser.setText("Security channel is broken.")
        self.ui.button_ls.setDisabled(True)
        self.ui.button_get.setDisabled(True)
        flag_broken = 1


if __name__ == '__main__':
    app = QApplication(sys.argv)

    # TCP连接句柄与会话密钥
    c_socket = None
    sess_key = b''

    # 信道状态标志
    flag_broken = 0

    main_window = CSETransWidget()
    login_window = CLoginWidget(main_window)
    login_window.show()

    app.exec()

    if flag_broken == 0:
        c_socket.close()

    sys.exit()
