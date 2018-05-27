#-------------------------------------------------
#
# Project created by QtCreator 2018-04-06T03:09:54
#
#-------------------------------------------------

QT       += core gui network

CONFIG +=  c++14 openssl

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = YourFriendlyDNS
TEMPLATE = app

VERSION = 2.1.3
QMAKE_TARGET_COMPANY = freedom based software co.
QMAKE_TARGET_PRODUCT = YourFriendlyDNS
QMAKE_TARGET_DESCRIPTION = A local encrypting, caching and proxying dns proxy
QMAKE_TARGET_COPYRIGHT = 2018
DEFINES += APP_VERSION=\\\"$$VERSION\\\"

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS
#comment this next line out if you need to debug it if somethings not quite right (you'll get the qDebug() output then [and on macOS it has to be a debug build too for some reason])
DEFINES += QT_NO_DEBUG_OUTPUT

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

DEFINES += SODIUM_STATIC
INCLUDEPATH += libsodium/include
#You must compile libsodium (version 1.0.16 is what I used) and place compiled library in the project directory for simplicity.
#The 'libsodium' folder, or on Android-armeabi-v7a the 'libsodium-android-armv7-a' folder, or on Android-x86 the 'libsodium-android-i686' directory.

#Uncomment next line when building for Windows, and for building for Android comment it (It doesn't expect -L or -l just the lib directly)
#LIBS += $$PWD/libsodium/libsodium.lib

#Uncomment next line when building for Linux/Mac, and for building for Android comment it
LIBS += -L$$PWD/libsodium -lsodium

#Uncomment next line when building for iOS (comment others except below)
#LIBS += -L$$PWD/libsodium-ios/lib -lsodium

contains(ANDROID_TARGET_ARCH,armeabi-v7a) {
    #When building for Android-armv7: If neccessary change path to match where you copied the compiled libsodium to if not the same place below
    LIBS += -L $$PWD/libsodium-android-armv7-a/lib -lsodium
    ANDROID_EXTRA_LIBS = \
        $$PWD/libsodium-android-armv7-a/lib/libsodium.so
}

contains(ANDROID_TARGET_ARCH,x86) {
    #When building for Android-x86: If neccessary change path to match where you copied the compiled libsodium to if not the same place below
    LIBS += -L $$PWD/libsodium-android-i686/lib -lsodium
    ANDROID_EXTRA_LIBS = \
        $$PWD/libsodium-android-i686/lib/libsodium.so
}

SOURCES += \
        main.cpp \
        dnsserverwindow.cpp \
    smalldnsserver.cpp \
    settingswindow.cpp \
    initialresponse.cpp \
    indexhtml.cpp \
    smallhttpserver.cpp \
    messagesthread.cpp \
    cacheviewer.cpp \
    dnscrypt.cpp \
    providersourcerstampconverter.cpp

HEADERS += \
        dnsserverwindow.h \
    smalldnsserver.h \
    settingswindow.h \
    initialresponse.h \
    indexhtml.h \
    smallhttpserver.h \
    androidsuop.h \
    messagesthread.h \
    cacheviewer.h \
    dnsinfo.h \
    dnscrypt.h \
    buffer.h \
    providersourcerstampconverter.h

FORMS += \
        dnsserverwindow.ui \
    settingswindow.ui \
    indexhtml.ui \
    cacheviewer.ui \
    providersourcerstampconverter.ui

CONFIG += mobility
MOBILITY = 

DISTFILES += \
    GPLv2.txt \
    android/AndroidManifest.xml \
    android/gradle/wrapper/gradle-wrapper.jar \
    android/gradlew \
    android/res/values/libs.xml \
    android/build.gradle \
    android/gradle/wrapper/gradle-wrapper.properties \
    android/gradlew.bat

RESOURCES += \
    images.qrc

ANDROID_PACKAGE_SOURCE_DIR = $$PWD/android

