#-------------------------------------------------
#
# Project created by QtCreator 2018-04-06T03:09:54
#
#-------------------------------------------------

QT       += core gui network

CONFIG +=  c++14

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = YourFriendlyDNS
TEMPLATE = app

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS
#comment this next line out if you need to debug it if somethings not quite right (you'll get the qDebug() output then)
#DEFINES += QT_NO_DEBUG_OUTPUT

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0


SOURCES += \
        main.cpp \
        dnsserverwindow.cpp \
    smalldnsserver.cpp \
    settingswindow.cpp \
    initialresponse.cpp \
    indexhtml.cpp \
    smallhttpserver.cpp \
    messagesthread.cpp

HEADERS += \
        dnsserverwindow.h \
    smalldnsserver.h \
    settingswindow.h \
    initialresponse.h \
    indexhtml.h \
    smallhttpserver.h \
    androidsuop.h \
    messagesthread.h

FORMS += \
        dnsserverwindow.ui \
    settingswindow.ui \
    indexhtml.ui

CONFIG += mobility
MOBILITY = 

DISTFILES += \
    GPLv2.txt

RESOURCES += \
    images.qrc

