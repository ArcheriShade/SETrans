import sys
from socket import *

from PySide6.QtWidgets import QApplication, QWidget
from ui_login import Ui_Login

from flag import *

SERVER_ADDR = ("10.10.10.1", 7777)  # 服务器地址
CHUNK_SIZE = 1024                   # 传输数据大小


class CLoginWidget(QWidget):
    def __init__(self):
        global c_socket
        super().__init__()
        self.ui = Ui_Login()
        self.ui.setupUi(self)

        # 绑定button函数
        self.ui.button_signup.clicked.connect(self.signUp)

        # 建立TCP连接
        c_socket = socket(AF_INET, SOCK_STREAM)
        c_socket.connect(SERVER_ADDR)
        self.testCode(self.recvData())

    # def sessKeyInit():


    def signUp(self):
        # 只进行简单的非空校验
        username = self.ui.editline_user.text().strip()
        password = self.ui.editline_pwd.text().strip()
        if len(username) != 0 and len(password) != 0:
            info = "Registration succeeded!"
        else:
            info = "Username or password cannot be empty."

        self.ui.text_browser.setText(info)
        self.ui.editline_pwd.clear()

    def recvData(self):
        """
        接收数据
        """
        data = c_socket.recv(CHUNK_SIZE)
        return data

    def testCode(self, data):
        code = data[0].to_bytes(1, 'big')
        if code == ACON_LOGIN:
            self.ui.text_browser.setText("Login OK!")
        else:
            self.ui.text_browser.setText("Oops!")
        c_socket.close()


if __name__ == '__main__':
    app = QApplication(sys.argv)

    c_socket = None
    # c_socket = socket(AF_INET, SOCK_STREAM)
    # c_socket.connect(SERVER_ADDR)

    login_window = CLoginWidget()
    login_window.show()

    sys.exit(app.exec())
