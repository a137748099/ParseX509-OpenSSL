#include <iostream>
#include <fstream>
#include <algorithm>
#include "x509certificate.h"
using namespace std;

string readBinaryFile(const char *filePath) {
    string fileData;
    std::ifstream is (filePath, std::ifstream::binary);
    if (is) {
        is.seekg (0, is.end);
        int length = is.tellg();
        is.seekg (0, is.beg);
        char * buffer = new char [length];
        is.read (buffer,length);

        if (is) {
            fileData = string(buffer, length);
        }
        is.close();
        delete[] buffer;
    }

    return fileData;
}


int main()
{
//    X509Certificate x509Cert("/home/song/Qt-Project/x509Cert/test-cert/baidu.cer", 0);
    X509Certificate x509Cert("E:/git/x509/test-cert/baidu.cer", 0);
    cout << "song" << x509Cert.isNull() << endl;
    cout << "song" << "Ver" << x509Cert.version() << endl;
    cout << "song" << "serialNumber" << x509Cert.serialNumber().c_str() << endl;
    cout << "song" << "subject" << x509Cert.subject().c_str() << endl;
    cout << "song" << "issuer" << x509Cert.issuer().c_str() << endl;
    cout << "song" << "notbefor" << x509Cert.notBefor().c_str() << endl;
    cout << "song" << "notAfter" << x509Cert.notAfter().c_str() << endl;
    cout << "song" << "publicKeyVaule" << x509Cert.publicKeyValue().c_str() << endl;
    cout << "song" << "publicKeyType" << x509Cert.publicKeyType().c_str() << endl;
    cout << "song" << "signAlgType" << x509Cert.signAlgType().c_str() << endl;
    cout << "song" << "sign value" << x509Cert.signValue().c_str() << endl;
    x509Cert.toDer();
    x509Cert.toPem();
    x509Cert.toText();
    cout << "song" << "Sha1" << x509Cert.digest(X509Certificate::Hash_Sha1).c_str() << endl;
    cout << "song" << "Sha256" << x509Cert.digest(X509Certificate::Hash_Sha256).c_str() << endl;
    cout << "song" << "SM3" << x509Cert.digest(X509Certificate::Hash_SM3).c_str() << endl;

    vector<X509CertificateExtension> exts = x509Cert.extensions();
    for (const auto certExt : exts) {
        cout << "song" << certExt.oid().c_str() << certExt.name().c_str() << certExt.value().c_str() << endl;
        switch (certExt.methodType()) {
        case X509CertificateExtension::Ext_String:
            cout << "song"  << "Text:" << certExt.toString().c_str() << endl;
            break;
        case X509CertificateExtension::Ext_Vector:
            for(auto text : certExt.toVector()) {
                cout << "song"  << "Vec Text:" << text.c_str() << endl;
            }
            break;
        case X509CertificateExtension::Ext_Map:
        {
            auto map = certExt.toMap();
            auto iter = map.begin();
            for(; iter != map.end(); ++iter) {
                cout << "song"  << "Map Key:" << iter->first.c_str() << "Map Value:" << iter->second.c_str() << endl;
            }
        }
            break;
        default:
            break;
        }
    }

    char priKey[2048] = {0};
    int priKeyLen = 2048;
    X509Certificate *x = new X509Certificate;
    cout << "song" << x->isNull();
    vector<X509Certificate> caCerts;
    //    bool import = X509Certificate::importPkcs12("D:/cert-test/test1.pfx", 0, priKey, priKeyLen, x, caCerts, "123456");

//    auto fileData = readBinaryFile("/home/song/Qt-Project/x509Cert/test-cert/test1.pfx");
    auto fileData = readBinaryFile("E:/git/x509/test-cert/test1.pfx");
    bool import = X509Certificate::importPkcs12(fileData.c_str(), fileData.size(), priKey, priKeyLen, x, caCerts, "123456");

    X509Certificate testCert;
    testCert = *x;
    delete x;
    cout << "song" << "serialNumber" << testCert.serialNumber().c_str() << endl;

    vector<X509Certificate> certVec;
//    import = X509Certificate::importP7b("/home/song/Qt-Project/x509Cert/test-cert/test_all.p7b", 0, certVec);
    import = X509Certificate::importP7b("E:/git/x509/test-cert/test_all.p7b", 0, certVec);

    auto sysCaCerts = X509Certificate::systemCaCertificates();
    //    cout << "song" << sysCaCerts.size();
    for (const auto caCert : sysCaCerts) {
        auto exts = caCert.extensions();
    }

    auto chainFileData = readBinaryFile("C:/Users/Songxd/Desktop/chain22.pem");
    auto certsVec = X509Certificate::splitCertChain(chainFileData);
	//X509Certificate x509Cert("/home/song/Desktop/baidu.cer", 0);
    //X509Certificate middleCert("/home/song/Desktop/gsorganizationvalsha2g2r1.pem", 0);
    //X509Certificate rootCert("/home/song/Desktop/333.cer", 0);
    //vector<X509Certificate> certChain = {x509Cert, middleCert, rootCert};
    //std::reverse(certChain.begin(), certChain.end());
    //auto verifyResult = X509Certificate::verify(x509Cert, certChain);
    //cout << "verify" << verifyResult;
    return 0;
}
