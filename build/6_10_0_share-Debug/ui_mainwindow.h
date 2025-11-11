/********************************************************************************
** Form generated from reading UI file 'mainwindow.ui'
**
** Created by: Qt User Interface Compiler version 6.10.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MAINWINDOW_H
#define UI_MAINWINDOW_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QLabel>
#include <QtWidgets/QListWidget>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QPlainTextEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_MainWindow
{
public:
    QWidget *centralwidget;
    QGroupBox *groupCA;
    QPushButton *btnGenCA;
    QPushButton *btnIssueCerts;
    QPlainTextEdit *plainCAInfo;
    QGroupBox *groupAlice;
    QLabel *labelAliceFiles;
    QListWidget *listAliceFiles;
    QLabel *labelMessage;
    QPlainTextEdit *plainAliceMessage;
    QPushButton *btnReqBobCert;
    QPushButton *btnEncrypt;
    QPlainTextEdit *plainAliceLog;
    QPushButton *btnSend;
    QGroupBox *groupBob;
    QLabel *labelBobFiles;
    QListWidget *listBobFiles;
    QPushButton *btnDecrypt;
    QLabel *labelDecrypted;
    QPlainTextEdit *plainDecrypted;
    QPushButton *btnVerify;
    QPlainTextEdit *plainBobLog;
    QMenuBar *menubar;
    QStatusBar *statusbar;

    void setupUi(QMainWindow *MainWindow)
    {
        if (MainWindow->objectName().isEmpty())
            MainWindow->setObjectName("MainWindow");
        MainWindow->resize(1100, 700);
        centralwidget = new QWidget(MainWindow);
        centralwidget->setObjectName("centralwidget");
        groupCA = new QGroupBox(centralwidget);
        groupCA->setObjectName("groupCA");
        groupCA->setGeometry(QRect(20, 20, 330, 220));
        btnGenCA = new QPushButton(groupCA);
        btnGenCA->setObjectName("btnGenCA");
        btnGenCA->setGeometry(QRect(10, 30, 150, 30));
        btnIssueCerts = new QPushButton(groupCA);
        btnIssueCerts->setObjectName("btnIssueCerts");
        btnIssueCerts->setGeometry(QRect(170, 30, 150, 30));
        plainCAInfo = new QPlainTextEdit(groupCA);
        plainCAInfo->setObjectName("plainCAInfo");
        plainCAInfo->setGeometry(QRect(10, 70, 310, 130));
        plainCAInfo->setReadOnly(true);
        groupAlice = new QGroupBox(centralwidget);
        groupAlice->setObjectName("groupAlice");
        groupAlice->setGeometry(QRect(20, 260, 520, 380));
        labelAliceFiles = new QLabel(groupAlice);
        labelAliceFiles->setObjectName("labelAliceFiles");
        labelAliceFiles->setGeometry(QRect(10, 20, 100, 16));
        listAliceFiles = new QListWidget(groupAlice);
        listAliceFiles->setObjectName("listAliceFiles");
        listAliceFiles->setGeometry(QRect(10, 40, 240, 120));
        labelMessage = new QLabel(groupAlice);
        labelMessage->setObjectName("labelMessage");
        labelMessage->setGeometry(QRect(260, 20, 200, 16));
        plainAliceMessage = new QPlainTextEdit(groupAlice);
        plainAliceMessage->setObjectName("plainAliceMessage");
        plainAliceMessage->setGeometry(QRect(260, 40, 240, 120));
        btnReqBobCert = new QPushButton(groupAlice);
        btnReqBobCert->setObjectName("btnReqBobCert");
        btnReqBobCert->setGeometry(QRect(10, 170, 120, 30));
        btnEncrypt = new QPushButton(groupAlice);
        btnEncrypt->setObjectName("btnEncrypt");
        btnEncrypt->setGeometry(QRect(140, 170, 110, 30));
        plainAliceLog = new QPlainTextEdit(groupAlice);
        plainAliceLog->setObjectName("plainAliceLog");
        plainAliceLog->setGeometry(QRect(10, 210, 490, 150));
        plainAliceLog->setReadOnly(true);
        btnSend = new QPushButton(groupAlice);
        btnSend->setObjectName("btnSend");
        btnSend->setGeometry(QRect(260, 170, 110, 30));
        groupBob = new QGroupBox(centralwidget);
        groupBob->setObjectName("groupBob");
        groupBob->setGeometry(QRect(560, 20, 520, 620));
        labelBobFiles = new QLabel(groupBob);
        labelBobFiles->setObjectName("labelBobFiles");
        labelBobFiles->setGeometry(QRect(10, 20, 100, 16));
        listBobFiles = new QListWidget(groupBob);
        listBobFiles->setObjectName("listBobFiles");
        listBobFiles->setGeometry(QRect(10, 40, 200, 120));
        btnDecrypt = new QPushButton(groupBob);
        btnDecrypt->setObjectName("btnDecrypt");
        btnDecrypt->setGeometry(QRect(220, 40, 110, 30));
        labelDecrypted = new QLabel(groupBob);
        labelDecrypted->setObjectName("labelDecrypted");
        labelDecrypted->setGeometry(QRect(10, 170, 120, 16));
        plainDecrypted = new QPlainTextEdit(groupBob);
        plainDecrypted->setObjectName("plainDecrypted");
        plainDecrypted->setGeometry(QRect(10, 190, 500, 160));
        plainDecrypted->setReadOnly(true);
        btnVerify = new QPushButton(groupBob);
        btnVerify->setObjectName("btnVerify");
        btnVerify->setGeometry(QRect(10, 360, 120, 30));
        plainBobLog = new QPlainTextEdit(groupBob);
        plainBobLog->setObjectName("plainBobLog");
        plainBobLog->setGeometry(QRect(10, 400, 500, 200));
        plainBobLog->setReadOnly(true);
        MainWindow->setCentralWidget(centralwidget);
        menubar = new QMenuBar(MainWindow);
        menubar->setObjectName("menubar");
        menubar->setGeometry(QRect(0, 0, 1100, 21));
        MainWindow->setMenuBar(menubar);
        statusbar = new QStatusBar(MainWindow);
        statusbar->setObjectName("statusbar");
        MainWindow->setStatusBar(statusbar);

        retranslateUi(MainWindow);

        QMetaObject::connectSlotsByName(MainWindow);
    } // setupUi

    void retranslateUi(QMainWindow *MainWindow)
    {
        MainWindow->setWindowTitle(QCoreApplication::translate("MainWindow", "Hybrid Protocol GUI", nullptr));
        groupCA->setTitle(QCoreApplication::translate("MainWindow", "Certification Authority (CA)", nullptr));
        btnGenCA->setText(QCoreApplication::translate("MainWindow", "Generate CA keys", nullptr));
        btnIssueCerts->setText(QCoreApplication::translate("MainWindow", "Issue certs (Alice,Bob)", nullptr));
        groupAlice->setTitle(QCoreApplication::translate("MainWindow", "Alice (sender)", nullptr));
        labelAliceFiles->setText(QCoreApplication::translate("MainWindow", "Alice files", nullptr));
        labelMessage->setText(QCoreApplication::translate("MainWindow", "Message to send", nullptr));
        btnReqBobCert->setText(QCoreApplication::translate("MainWindow", "Request Bob Cert", nullptr));
        btnEncrypt->setText(QCoreApplication::translate("MainWindow", "Encrypt", nullptr));
        btnSend->setText(QCoreApplication::translate("MainWindow", "Send", nullptr));
        groupBob->setTitle(QCoreApplication::translate("MainWindow", "Bob (receiver)", nullptr));
        labelBobFiles->setText(QCoreApplication::translate("MainWindow", "Bob files", nullptr));
        btnDecrypt->setText(QCoreApplication::translate("MainWindow", "Decrypt message", nullptr));
        labelDecrypted->setText(QCoreApplication::translate("MainWindow", "Decrypted message", nullptr));
        btnVerify->setText(QCoreApplication::translate("MainWindow", "Verify signature", nullptr));
    } // retranslateUi

};

namespace Ui {
    class MainWindow: public Ui_MainWindow {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MAINWINDOW_H
