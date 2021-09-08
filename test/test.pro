TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

win32: {
    INCLUDEPATH += ../x509Cert ../x509Cert/include
    LIBS += -L$$PWD/../x509Cert/lib/VC -llibssl32MTd -llibcrypto32MTd
}

unix: {
    LIBS += -lssl -lcrypto
}

SOURCES += \
        ../x509Cert/exts/x509certificateextension_p.cpp \
        ../x509Cert/x509certificate.cpp \
        ../x509Cert/x509certificate_p.cpp \
        main.cpp

HEADERS += \
    ../x509Cert/exts/x509certificateextension_p.h \
    ../x509Cert/x509certificate.h \
    ../x509Cert/x509certificate_p.h
