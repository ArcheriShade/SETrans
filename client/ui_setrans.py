# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'setrans.ui'
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
from PySide6.QtWidgets import (QApplication, QLabel, QListView, QPushButton,
    QSizePolicy, QTextBrowser, QWidget)

class Ui_SETrans(object):
    def setupUi(self, SETrans):
        if not SETrans.objectName():
            SETrans.setObjectName(u"SETrans")
        SETrans.resize(580, 374)
        sizePolicy = QSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(SETrans.sizePolicy().hasHeightForWidth())
        SETrans.setSizePolicy(sizePolicy)
        SETrans.setMinimumSize(QSize(580, 374))
        SETrans.setMaximumSize(QSize(580, 374))
        self.text_browser = QTextBrowser(SETrans)
        self.text_browser.setObjectName(u"text_browser")
        self.text_browser.setGeometry(QRect(280, 130, 260, 100))
        self.list_view = QListView(SETrans)
        self.list_view.setObjectName(u"list_view")
        self.list_view.setGeometry(QRect(40, 60, 200, 240))
        self.label_lv = QLabel(SETrans)
        self.label_lv.setObjectName(u"label_lv")
        self.label_lv.setGeometry(QRect(40, 30, 60, 20))
        font = QFont()
        font.setBold(True)
        self.label_lv.setFont(font)
        self.button_ls = QPushButton(SETrans)
        self.button_ls.setObjectName(u"button_ls")
        self.button_ls.setGeometry(QRect(40, 320, 75, 24))
        self.button_get = QPushButton(SETrans)
        self.button_get.setObjectName(u"button_get")
        self.button_get.setGeometry(QRect(165, 320, 75, 24))

        self.retranslateUi(SETrans)

        QMetaObject.connectSlotsByName(SETrans)
    # setupUi

    def retranslateUi(self, SETrans):
        SETrans.setWindowTitle(QCoreApplication.translate("SETrans", u"SETrans", None))
        self.label_lv.setText(QCoreApplication.translate("SETrans", u"File List", None))
        self.button_ls.setText(QCoreApplication.translate("SETrans", u"List", None))
        self.button_get.setText(QCoreApplication.translate("SETrans", u"Get", None))
    # retranslateUi

