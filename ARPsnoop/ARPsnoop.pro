QT -= gui

CONFIG += c++11 console
CONFIG -= app_bundle
LIBS += -lpcap
DEFINES += QT_DEPRECATED_WARNINGS
SOURCES += \
        main.cpp \
        pcap_test.cpp
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

HEADERS += \
    pcap_test.h
