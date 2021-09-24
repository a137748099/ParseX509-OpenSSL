#ifndef X509CERTIFICATE_P_H
#define X509CERTIFICATE_P_H

#include <string>
#include <map>
#include <vector>

#ifdef  __cplusplus
extern "C" {
#endif
#include <openssl/x509v3.h>
#ifdef  __cplusplus
}
#endif

using namespace std;

class X509Certificate;
class X509CertificateExtension_p;
class X509Certificate_p
{
public:
    X509Certificate_p(const char *cert, int len);
    ~X509Certificate_p();

    int version() const;
    string serialNumber() const;
    string subject() const;
    string subjectInfo(string dnKey);
    string issuer() const;
    string issuerInfor(string dnKey);
    string notBefor() const;
    string notAfter() const;
    string publicKeyValue() const;
    string publicKeyType() const;
    string signAlgType() const;
    string signValue() const;
    string digest(string type) const;

    vector<X509CertificateExtension_p *> extensions();

    string toDer() const;
    string toPem() const;
    string toText() const;

    static bool importPkcs12(const char *pfxFile, int len, char *priKey, int &priKeyLen,
                            X509Certificate *x509Cert, vector<X509Certificate> &caCerts,
                            const char *pass = "");
    static bool importP7b(const char *p7b, int len, vector<X509Certificate> &caCerts, int format = 0);

    static vector<X509Certificate> splitCertChain(const string &chains);

    static int verify(const X509Certificate &userCert, vector<X509Certificate> certificateChain);

    static vector<X509Certificate> systemCaCertificates();

private:
    X509 *initX509(const char *cert, int len);
    BIO* Mem2Bio(const char* lpBuf, const int nBufLen);

private:
    map<string, string> subjectMap;
    map<string, string> issuerMap;

private:
    X509 *m_pX509 = nullptr;
    vector<X509CertificateExtension_p *> m_certExtVec;
    bool m_bExtInit = false;
    friend class X509Certificate;
};

#endif // X509CERTIFICATE_P_H
