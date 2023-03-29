import sys
import json
import shutil
from socket import *
from concurrent.futures import ThreadPoolExecutor

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

from PySide6.QtWidgets import QApplication, QWidget, QAbstractItemView
from PySide6.QtCore import QStringListModel, QObject, Signal
from ui_login import Ui_Login
from ui_setrans import Ui_SETrans

from flag import *

SERVER_ADDR = ("10.10.10.1", 7777)  # 服务器地址
CHUNK_SIZE = 1024                   # 传输数据大小


# 获取文件线程
class getFileThread(QObject):
    finished = Signal(bool)

    def __init__(self, client, filename, length):
        super().__init__()
        self.client = client
        self.filename = filename
        self.length = length
    
    def run(self):
        res = self.client.getFile(self.filename, self.length)
        if res:
            self.finished.emit(True)
        else:
            self.finished.emit(False)


class Client:
    def __init__(self):
        # TCP连接句柄与会话密钥
        self.c_socket = None
        self.sess_key = b''
        # 信道状态标志
        self.flag_broken = False

    def seSessInit(self):
        """
        初始化安全信道
        """
        # 建立TCP连接
        self.c_socket = socket(AF_INET, SOCK_STREAM)
        self.c_socket.connect(SERVER_ADDR)

        # 接收server发来的数据
        data = self.c_socket.recv(CHUNK_SIZE)
        code, en_sess_key, signature = data[:1], data[1:257], data[257:]

        if code != CONN_KEYSEND:
            self.c_socket.send(CONN_CLOSE)
            self.c_socket.close()
            return False

        # 用client-私钥解密获得会话密钥
        with open("./keys/c_private.pem", 'rb') as file_obj:
            c_pri_key = RSA.import_key(file_obj.read())
        self.sess_key = PKCS1_OAEP.new(c_pri_key).decrypt(en_sess_key)

        # 用server-公钥验签
        digest = SHA256.new(self.sess_key)
        with open("./keys/s_public.pem", 'rb') as file_obj:
            s_pub_key = RSA.import_key(file_obj.read())
        # 验签成功返回None，否则抛出ValueError: Invalid signature
        try:
            pkcs1_15.new(s_pub_key).verify(digest, signature)
        except ValueError as e:
            self.c_socket.send(CONN_CLOSE)
            self.c_socket.close()
            return False
        else:
            self.c_socket.send(CONN_KEYRECV)
            return True

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

    def signUp(self, username, password):
        """
        用户注册
        """
        # 加密数据并发送
        data = ACON_SIGN + f"{username}/{password}".encode()
        cipher_data = self.encryptData(data)
        self.c_socket.send(cipher_data)

        # 接收服务端响应
        cipher_data = self.c_socket.recv(CHUNK_SIZE)
        data = self.decryptData(cipher_data)
        if data == -1:
            self.sessBroken()
            return "Broken"
        code = data[0].to_bytes(1, 'big')
        return code
    
    def login(self, username, password):
        """
        用户登录
        """
        # 加密数据并发送
        data = ACON_LOGIN + f"{username}/{password}".encode()
        cipher_data = self.encryptData(data)
        self.c_socket.send(cipher_data)

        # 接收服务端响应
        cipher_data = self.c_socket.recv(CHUNK_SIZE)
        data = self.decryptData(cipher_data)
        if data == -1:
            self.sessBroken()
            return "Broken"
        code = data[0].to_bytes(1, 'big')
        return code
    
    def recvEncData(self, length):
        """
        获取指定长度的加密数据
        """
        chunks = []
        recv_size = 0
        while recv_size < length:
            chunk = self.c_socket.recv(min(CHUNK_SIZE, length - recv_size))
            chunks.append(chunk)
            recv_size += len(chunk)
        cipher_data = b''.join(chunks)
        return cipher_data
    
    def getList(self):
        """
        获取文件列表
        """
        # 发送获取文件列表的信号
        data = FILE_LS
        cipher_data = self.encryptData(data)
        self.c_socket.send(cipher_data)

        # 接收服务端响应 - 加密数据长度
        cipher_data = self.c_socket.recv(CHUNK_SIZE)
        data = self.decryptData(cipher_data)
        if data == -1:
            self.sessBroken()
            return "Broken"
        code = data[0].to_bytes(1, 'big')
        if code != FILE_LEN:
            self.sessBroken()
            return "Broken"
        length = int.from_bytes(data[1:], 'big')

        # 发送确认接收数据
        data = FILE_RECV
        cipher_data = self.encryptData(data)
        self.c_socket.send(cipher_data)

        # 根据数据长度，接收加密数据
        cipher_data = self.recvEncData(length)
        data = self.decryptData(cipher_data)
        code = data[0].to_bytes(1, 'big')
        if code == FILE_TRANS:
            return json.loads(data[1:])
        else:
            self.sessBroken()
            return "Broken"
    
    def checkFile(self, filename):
        """
        判断文件是否存在，存在则返回加密文件长度
        """
        # 发送获取文件的信号
        data = FILE_GET + filename.encode()
        cipher_data = self.encryptData(data)
        self.c_socket.send(cipher_data)

        # 接收服务端响应 - 加密文件长度
        cipher_data = self.c_socket.recv(CHUNK_SIZE)
        data = self.decryptData(cipher_data)
        if data == -1:
            self.sessBroken()
            return "Broken"
        
        code = data[0].to_bytes(1, 'big')
        if code == FILE_LEN:
            length = int.from_bytes(data[1:], 'big')
            return length
        elif code == FILE_NEXIS:
            return FILE_NEXIS
        else:
            self.sessBroken()
            return "Broken"

    def getFile(self, filename, length):
        """
        根据长度获取加密文件
        """
        # 发送确认接收数据
        data = FILE_RECV
        cipher_data = self.encryptData(data)
        self.c_socket.send(cipher_data)

        # 根据数据长度，接收加密数据
        cipher_data = self.recvEncData(length)
        data = self.decryptData(cipher_data)
        code = data[0].to_bytes(1, 'big')
        if code == FILE_TRANS:
            file_data = data[1:]
            with open(f"./filehub/{filename}", 'wb') as file_obj:
                file_obj.write(file_data)
            return True
        else:
            self.sessBroken()
            return False

    def sessBroken(self):
        """
        安全信道破损，关闭连接
        """
        self.c_socket.close()
        self.flag_broken = True


class CLoginWidget(QWidget):
    def __init__(self, client, main_ui):
        super().__init__()
        self.ui = Ui_Login()
        self.ui.setupUi(self)

        self.client = client
        self.main_ui = main_ui

        # 绑定button函数
        self.ui.button_signup.clicked.connect(self.doSignUp)
        self.ui.button_login.clicked.connect(self.doLogin)

        # 建立安全信道
        self.doSeSessInit()

    def doSeSessInit(self):
        """
        界面端执行建立安全信道
        """
        if self.client.seSessInit():
            self.ui.text_browser.setText("Security channel setup completed.")
        else:
            self.ui.text_browser.setText("Failed to establish a secure channel.")

    def doSignUp(self):
        """
        界面端执行用户注册
        """
        # 只进行简单的非空校验
        username = self.ui.editline_user.text().strip()
        password = self.ui.editline_pwd.text().strip()
        if len(username) == 0 or len(password) == 0:
            self.ui.text_browser.setText("Username or password cannot be empty.")
            return -1
        else:
            res = self.client.signUp(username, password)
            if res == "Broken":
                self.sessBroken()
                return False
            elif res == ACON_OK:
                self.ui.text_browser.setText("Registration succeeded.")
                self.ui.editline_pwd.clear()
                return True
            elif res == ACON_FMATERR:
                self.ui.text_browser.setText("Username or password format error.")
                self.ui.editline_pwd.clear()
                return False
            elif res == ACON_NEXIS:
                self.ui.text_browser.setText("Username already exists.")
                self.ui.editline_pwd.clear()
                return False
            else:
                self.ui.text_browser.setText("Registration failed.")
                self.ui.editline_pwd.clear()
                return False

    def doLogin(self):
        """
        界面端执行用户登录
        """
        # 只进行简单的非空校验
        username = self.ui.editline_user.text().strip()
        password = self.ui.editline_pwd.text().strip()
        if len(username) == 0 or len(password) == 0:
            self.ui.text_browser.setText("Username or password cannot be empty.")
            return False
        else:
            res = self.client.login(username, password)
            if res == "Broken":
                self.sessBroken()
                return False
            elif res == ACON_OK:
                self.ui.text_browser.setText("Login succeeded.")
                self.close()
                self.main_ui.show()
                return True
            elif res == ACON_FMATERR:
                self.ui.text_browser.setText("Username or password format error.")
                self.ui.editline_pwd.clear()
                return False
            elif res == ACON_NPERR:
                self.ui.text_browser.setText("Username or password error.")
                self.ui.editline_pwd.clear()
                return False
            else:
                self.ui.text_browser.setText("Login failed.")
                self.ui.editline_pwd.clear()
                return False

    def sessBroken(self):
        """
        安全信道破损，给出信息，禁用按钮
        """
        self.ui.text_browser.setText("Security channel is broken.")
        self.ui.button_login.setDisabled(True)
        self.ui.button_signup.setDisabled(True)


class CSETransWidget(QWidget):
    def __init__(self, client):
        super().__init__()
        self.ui = Ui_SETrans()
        self.ui.setupUi(self)

        self.client = client

        # 文件信息列表、已选择文件名称、已选择文件大小
        self.files_info = []
        self.selected = ""
        self.selected_size = 0
        self.slm = QStringListModel()

        # 绑定button函数
        self.ui.button_ls.clicked.connect(self.doGetList)
        self.ui.button_get.clicked.connect(self.doGetFile)
        self.ui.list_view.clicked.connect(self.clickList)
        # 未选择文件禁止get（前端）
        self.ui.button_get.setDisabled(True)
        # 禁止双击listView编辑
        self.ui.list_view.setEditTriggers(QAbstractItemView.NoEditTriggers)

    def doGetList(self):
        """
        界面端执行获取文件列表
        """
        res = self.client.getList()
        if res == "Broken":
            self.sessBroken()
            return False
        else:
            self.files_info = res

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
            return True

    def doGetFile(self):
        """
        界面端执行发送获取文件信号及目标文件名
        """
        self.ui.text_browser.setText(f"Getting file: {self.selected}")
        self.ui.button_ls.setDisabled(True)
        self.ui.button_get.setDisabled(True)

        res = self.client.checkFile(self.selected)
        if res == "Broken":
            self.sessBroken()
            return False
        elif res == FILE_NEXIS:
            self.ui.text_browser.setText("File does not exist.")
            return False
        else:
            length = res
            self.t_pool = ThreadPoolExecutor()
            self.get_file_t = getFileThread(self.client, self.selected, length)
            self.get_file_t.finished.connect(self.doGetFileFinished)
            self.t_pool.submit(self.get_file_t.run)
    
    def doGetFileFinished(self, res):
        if res:
            self.ui.text_browser.setText(f"Successfully obtained file '{self.selected}'.")
            self.ui.button_ls.setEnabled(True)
            self.ui.button_get.setEnabled(True)
            return True
        else:
            self.ui.text_browser.setText(f"Could not obtained file '{self.selected}'.")
            return False

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

    def sessBroken(self):
        """
        界面端执行安全信道破损，给出信息，禁用按钮
        """
        self.ui.text_browser.setText("Security channel is broken.")
        self.ui.button_ls.setDisabled(True)
        self.ui.button_get.setDisabled(True)


if __name__ == '__main__':
    app = QApplication(sys.argv)

    client = Client()
    main_window = CSETransWidget(client)
    login_window = CLoginWidget(client, main_window)
    login_window.show()

    app.exec()

    if client.flag_broken:
        client.c_socket.close()

    sys.exit()
