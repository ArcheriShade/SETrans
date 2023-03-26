import os
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


class CLoginWidget(QWidget):
    def __init__(self, main_ui):
        super().__init__()
        self.ui = Ui_Login()
        self.ui.setupUi(self)
        self.main_ui = main_ui

        # 绑定button函数
        self.ui.button_login.clicked.connect(self.login)

        # 建立安全信道
        self.seSessInit()

    def login(self):
        self.close()
        self.main_ui.show()

        # username = self.ui.editline_user.text()
        # password = self.ui.editline_pwd.text()
        #
        # if username == "Archeri" and password == "password":
        #     print("login successes.")
        #     self.close()
        #     self.main_ui.show()
        # else:
        #     return -1

    def seSessInit(self):
        global c_socket
        global sess_key
        c_socket = True

        print("seSessInit:", c_socket)
        print("seSessInit:", sess_key)


class CSETransWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.ui = Ui_SETrans()
        self.ui.setupUi(self)

        self.files_info = []
        self.slm = QStringListModel()
        self.selected = ""
        self.selected_size = 0

        # 测试连接情况
        self.showConnInfo()

        # 绑定button函数
        self.ui.button_ls.clicked.connect(self.getList)
        self.ui.button_get.clicked.connect(self.getFile)
        self.ui.button_get.setDisabled(True)
        self.ui.list_view.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.ui.list_view.clicked.connect(self.clickedList)

    def showConnInfo(self):
        global c_socket
        global sess_key
        print("main showConnInfo:", c_socket)
        print("main showConnInfo:", sess_key)

    def getList(self):
        global c_socket
        global sess_key
        print("main ls:", c_socket)
        print("main ls:", sess_key)

        # 模拟列表传输
        s_files = os.listdir("./filehub")
        s_fs_info = []
        for file in s_files:
            s_fs_info.append((file, os.stat(f"./filehub/{file}").st_size))
        data = json.dumps(s_fs_info).encode()
        # 获取加密信息
        self.files_info = json.loads(data)

        # test
        self.files_info.append(("big file.bin", 358548297728))

        files_name = []
        for info in self.files_info:
            files_name.append(info[0])

        self.slm.setStringList(files_name)
        self.ui.list_view.setModel(self.slm)

        self.ui.text_browser.clear()
        self.ui.button_get.setDisabled(True)
        pass

    def clickedList(self, qModelIndex):
        self.selected = self.files_info[qModelIndex.row()][0]
        self.selected_size = self.files_info[qModelIndex.row()][1]

        msg = ""
        total_b, used_b, free_b = shutil.disk_usage("./filehub")
        if len(self.selected) != 0:
            msg = f"点击了：{self.selected}\n文件大小：{self.selected_size}"
            if free_b > self.selected_size:
                msg += "\n空间足够"
                self.ui.button_get.setEnabled(True)
            else:
                msg += "\n空间不足"
                self.ui.button_get.setDisabled(True)
        self.ui.text_browser.setText(msg)
        pass

    def getFile(self):
        global c_socket
        global sess_key
        print("main get:", c_socket)
        print("main get:", sess_key)

        self.ui.text_browser.setText(f"获得文件：{self.selected}")
        pass


if __name__ == '__main__':
    app = QApplication(sys.argv)

    # TCP连接句柄与会话密钥
    c_socket = False
    print("第一次", c_socket)
    sess_key = "a key"

    main_window = CSETransWidget()
    login_window = CLoginWidget(main_window)
    login_window.show()

    app.exec()

    if c_socket:
        c_socket = False
        print("结束时还在连接，关闭后：", c_socket)

    sys.exit()
