#ifndef X509CERTIFICATEEXTENSION_P_H
#define X509CERTIFICATEEXTENSION_P_H

#include <string>
#include <vector>
#include <map>

using namespace std;

class X509CertificateExtension_p
{
public:
    X509CertificateExtension_p();

    enum Method {
        Me_String,
        Me_Vector,
        Me_Map
    };

    X509CertificateExtension_p &operator=(const X509CertificateExtension_p &other);

private:
    string m_oid;
    string m_name;
    string m_value;
    bool m_critical = false;

    Method m_method = Me_String;
    string m_i2sString;
    vector<string> m_i2vVec;
    multimap<string, string> m_i2vMap;

    friend class X509Certificate_p;
    friend class X509CertificateExtension;

};

#endif // X509CERTIFICATEEXTENSION_P_H
