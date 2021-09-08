CONFIG -= qt

TEMPLATE = lib
DEFINES += X509CERTIFICATE_LIBRARY

CONFIG += c++11

# The following define makes your compiler emit warnings if you use
# any Qt feature that has been marked deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

win32: {
    INCLUDEPATH += ../x509Cert ../x509Cert/include
    LIBS += -L$$PWD/../x509Cert/lib/VC -llibssl32MTd -llibcrypto32MTd
}

unix: {
    LIBS += -lssl -lcrypto
}

SOURCES += \
    ../x509Cert/exts/x509certificateextension_p.cpp \
    ../x509Cert/x509certificate_p.cpp \
    ../x509Cert/x509certificate.cpp

HEADERS += \
    ../x509Cert/exts/x509certificateextension_p.h \
    ../x509Cert/x509certificate_p.h \
    ../x509Cert/x509certificate.h

# Default rules for deployment.
unix {
    target.path = /usr/lib
}
!isEmpty(target.path): INSTALLS += target
