import sys

from PySide6.QtWidgets import QApplication, QWidget
from ui_login import Ui_Login


class CLoginWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Login()
        self.ui.setupUi(self)

        # 绑定button函数
        self.ui.button_signup.clicked.connect(self.signUp)

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


if __name__ == '__main__':
    app = QApplication(sys.argv)

    login_window = CLoginWidget()
    login_window.show()

    sys.exit(app.exec())
