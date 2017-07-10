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
    crypt_thread.cpp \
    asymmetric_cryptor.cpp \
    progress_tablemodel.cpp \
    progress_delegate.cpp \
    c_exception.cpp \
    crypto_io.cpp

HEADERS += \
        mainwindow.h \
    asymmetric_cryptor.h \
    crypt_thread.h \
    progress_tablemodel.h \
    progress_delegate.h \
    c_exception.h \
    crypto_io.h

FORMS += \
        mainwindow.ui

win32:{
    INCLUDEPATH += D:/dev/botan/include/botan-2
    LIBS += -LD:/dev/botan/lib
    LIBS += Advapi32.lib
    LIBS += user32.lib
    Debug:LIBS += botand.lib
    Release:LIBS += botan.lib
}

unix:{
    LIBS += -L/usr/local/lib
    LIBS += -lbotan
    QMAKE_CXXFLAGS += -std=c++1y
}
