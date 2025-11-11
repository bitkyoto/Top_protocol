QT       += core gui widgets

CONFIG   += c++17

# Пути к исходникам и хедерам
SOURCES += \
    main.cpp \
    mainwindow.cpp \
    rc4/RC4.cpp \
    rsa/RSA.cpp \
    md5/md5.cpp

HEADERS += \
    mainwindow.h \
    rc4/RC4.h \
    rsa/RSA.h \
    md5/md5.h

FORMS   += \
    mainwindow.ui

# Если у тебя есть подпапки с кодом, убедись, что они указаны правильно:
INCLUDEPATH += rc4 rsa md5
