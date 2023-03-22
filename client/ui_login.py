# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'login.ui'
##
## Created by: Qt User Interface Compiler version 6.4.2
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide6.QtCore import (QCoreApplication, QDate, QDateTime, QLocale,
    QMetaObject, QObject, QPoint, QRect,
    QSize, QTime, QUrl, Qt)
from PySide6.QtGui import (QBrush, QColor, QConicalGradient, QCursor,
    QFont, QFontDatabase, QGradient, QIcon,
    QImage, QKeySequence, QLinearGradient, QPainter,
    QPalette, QPixmap, QRadialGradient, QTransform)
from PySide6.QtWidgets import (QApplication, QLabel, QLineEdit, QPushButton,
    QSizePolicy, QTextBrowser, QWidget)

class Ui_Login(object):
    def setupUi(self, Login):
        if not Login.objectName():
            Login.setObjectName(u"Login")
        Login.resize(590, 170)
        sizePolicy = QSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(Login.sizePolicy().hasHeightForWidth())
        Login.setSizePolicy(sizePolicy)
        Login.setMinimumSize(QSize(590, 170))
        Login.setMaximumSize(QSize(590, 170))
        self.label_user = QLabel(Login)
        self.label_user.setObjectName(u"label_user")
        self.label_user.setGeometry(QRect(40, 30, 60, 20))
        font = QFont()
        font.setBold(True)
        self.label_user.setFont(font)
        self.label_pwd = QLabel(Login)
        self.label_pwd.setObjectName(u"label_pwd")
        self.label_pwd.setGeometry(QRect(40, 70, 60, 20))
        self.label_pwd.setFont(font)
        self.label_pwd.setMargin(-1)
        self.editline_user = QLineEdit(Login)
        self.editline_user.setObjectName(u"editline_user")
        self.editline_user.setGeometry(QRect(120, 30, 140, 20))
        self.editline_user.setMaxLength(16)
        self.editline_pwd = QLineEdit(Login)
        self.editline_pwd.setObjectName(u"editline_pwd")
        self.editline_pwd.setGeometry(QRect(120, 70, 140, 20))
        self.editline_pwd.setMaxLength(16)
        self.editline_pwd.setEchoMode(QLineEdit.Password)
        self.editline_pwd.setCursorMoveStyle(Qt.LogicalMoveStyle)
        self.text_browser = QTextBrowser(Login)
        self.text_browser.setObjectName(u"text_browser")
        self.text_browser.setGeometry(QRect(290, 30, 260, 100))
        self.button_login = QPushButton(Login)
        self.button_login.setObjectName(u"button_login")
        self.button_login.setGeometry(QRect(50, 110, 75, 24))
        self.button_signup = QPushButton(Login)
        self.button_signup.setObjectName(u"button_signup")
        self.button_signup.setGeometry(QRect(170, 110, 75, 24))

        self.retranslateUi(Login)

        QMetaObject.connectSlotsByName(Login)
    # setupUi

    def retranslateUi(self, Login):
        Login.setWindowTitle(QCoreApplication.translate("Login", u"Login", None))
        self.label_user.setText(QCoreApplication.translate("Login", u"Username", None))
        self.label_pwd.setText(QCoreApplication.translate("Login", u"Password", None))
        self.button_login.setText(QCoreApplication.translate("Login", u"Login", None))
        self.button_signup.setText(QCoreApplication.translate("Login", u"Sign Up", None))
    # retranslateUi

