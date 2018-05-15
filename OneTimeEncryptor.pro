#-------------------------------------------------
#
# Project created by QtCreator 2017-06-06T20:22:44
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = OneTimeEncryptor
TEMPLATE = app

# The following define makes your compiler emit warnings if you use
# any feature of Qt which as been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0


SOURCES += \
        main.cpp \
        mainwindow.cpp \
    key_generator.cpp \
    decryptor.cpp \
    encryptor.cpp \
    crypto_exception.cpp \
    secure_memory.cpp \
    symmetric_cryptor.cpp \
    crypt_thread.cpp \
    asymmetric_cryptor.cpp \
    progress_tablemodel.cpp \
    progress_delegate.cpp \
    c_exception.cpp \
    crypto_io.cpp \
    msg_cryptor.cpp

HEADERS += \
        mainwindow.h \
    key_generator.h \
    decryptor.h \
    encryptor.h \
    secure_memory.h \
    crypto_exception.h \
    symmetric_cryptor.h \
    asymmetric_cryptor.h \
    crypt_thread.h \
    progress_tablemodel.h \
    progress_delegate.h \
    c_exception.h \
    crypto_io.h \
    msg_cryptor.h

FORMS += \
        mainwindow.ui

win32:{
    INCLUDEPATH += C:/OpenSSL-Win32/include
    LIBS += -LC:/OpenSSL-Win32/lib/VC
    Release:LIBS += libcrypto32MD.lib libssl32MD.lib
    Debug:LIBS += libcrypto32MDd.lib libssl32MDd.lib
}

unix:{
    LIBS += -L/usr/local/lib
    LIBS += -lcrypto -lssl
    QMAKE_CXXFLAGS += -std=c++1y
}
