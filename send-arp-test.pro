TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap

SOURCES += \
	arphdr.cpp \
	ethhdr.cpp \
	get_myinfo.cpp \
	ip.cpp \
	mac.cpp \
	main.cpp \
	transceive_arp.cpp

HEADERS += \
	arphdr.h \
	ethhdr.h \
	get_myinfo.h \
	ip.h \
	mac.h \
	transceive_arp.h
