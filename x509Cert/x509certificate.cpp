#include "x509certificate.h"
#include "x509certificate_p.h"
#include "exts/x509certificateextension_p.h"
#include <assert.h>
#include <map>

static map<int, string> dnMap = {{X509Certificate::Organization, "O"},
                               {X509Certificate::CommonName, "CN"},
                               {X509Certificate::LocalityName, "L"},
                               {X509Certificate::OrganizationalUnitName, "OU"},
                               {X509Certificate::CountryName, "C"},
                               {X509Certificate::StateOrProvinceName, "ST"},
                               {X509Certificate::DistinguishedNameQualifier, "dnQualifier"},
                               {X509Certificate::SerialNumber, "serialNumber"},
                               {X509Certificate::EmailAddress, "emailAddress"}};

static map<int, string> hashTypeMap = {{X509Certificate::Hash_Sha1, "Sha1"},
                                       {X509Certificate::Hash_Sha256, "Sha256"},
                                       {X509Certificate::Hash_SM3, "SM3"}};

X509Certificate::X509Certificate()
{

}

X509Certificate::X509Certificate(const char *cert, int len):
    p(make_shared<X509Certificate_p>(reinterpret_cast<const char *>(cert), len))
{

}

X509Certificate::X509Certificate(const X509Certificate &other)
{
    p = other.p;
}

X509Certificate &X509Certificate::operator=(const X509Certificate &other)
{
    //p为智能指针，浅拷贝后对象仍存在
    p = other.p;
    return *this;
}

bool X509Certificate::operator==(const X509Certificate &other) const
{
    if(!other.isNull())
        return false;
    return p->toDer() == other.p->toDer();
}

bool X509Certificate::isNull() const
{    
    return p.get() == nullptr || (p && p->m_pX509 == nullptr);
}

void *X509Certificate::handle() const
{
    return p->m_pX509;
}

int X509Certificate::version() const
{
    assert(p != 0);
    return p->version();
}

string X509Certificate::serialNumber() const
{
    assert(p != 0);
    return p->serialNumber();
}

string X509Certificate::subject() const
{
    assert(p != 0);
    return p->subject();
}

string X509Certificate::subjectInfo(X509Certificate::SubjectInfo subject) const
{
    assert(p != 0);
    return p->subjectInfo(dnMap[subject]);
}

string X509Certificate::subjectDisplyName() const
{
    assert(p != 0);
    return p->subjectInfo("CN");
}

string X509Certificate::issuer() const
{
    assert(p != 0);
    return p->issuer();
}

string X509Certificate::issuerInfo(X509Certificate::SubjectInfo issuer) const
{
    assert(p != 0);
    return p->issuerInfor(dnMap[issuer]);
}

string X509Certificate::issuerDisplyName() const
{
    assert(p != 0);
    return p->issuerInfor("CN");
}


string X509Certificate::notBefor() const
{
    assert(p != 0);
    return p->notBefor();
}

string X509Certificate::notAfter() const
{
    assert(p != 0);
    return p->notAfter();
}


string X509Certificate::digest(X509Certificate::HashType type) const
{
    assert(p != 0);
    return p->digest(hashTypeMap[type]);
}

string X509Certificate::publicKeyValue() const
{
    assert(p != 0);
    return p->publicKeyValue();
}

string X509Certificate::publicKeyType() const
{
    assert(p != 0);
    return p->publicKeyType();
}

string X509Certificate::signAlgType() const
{
    assert(p != 0);
    return p->signAlgType();
}

string X509Certificate::signValue() const
{
    assert(p != 0);
    return p->signValue();
}

vector<X509CertificateExtension> X509Certificate::extensions() const
{
    assert(p != 0);
    vector<X509CertificateExtension> exts;
    auto extVec = p->extensions();
    for(auto certExt : extVec) {
        X509CertificateExtension ext;
        ext.p = certExt;
        exts.push_back(ext);
    }

    return exts;
}

std::string X509Certificate::toDer() const
{
    assert(p != 0);
    return p->toDer();
}

std::string X509Certificate::toPem() const
{
    assert(p != 0);
    return p->toPem();
}

string X509Certificate::toText() const
{
    assert(p != 0);
    return p->toText();
}

bool X509Certificate::importPkcs12(const char *pfxFile, int len, char *priKey, int &priKeyLen, X509Certificate *x509Cert, vector<X509Certificate> &caCerts, const char *pass)
{
    return X509Certificate_p::importPkcs12(pfxFile, len, priKey, priKeyLen, x509Cert, caCerts, pass);
}

bool X509Certificate::importP7b(const char *p7b, int len, vector<X509Certificate> &caCerts)
{
    if(!X509Certificate_p::importP7b(p7b, len, caCerts)) {
        if(!X509Certificate_p::importP7b(p7b, len, caCerts, 1)) {
            return false;
        }
    }
    return true;
}

vector<X509Certificate> X509Certificate::splitCertChain(const string &chains)
{
    return X509Certificate_p::splitCertChain(chains);
}

int X509Certificate::verify(const X509Certificate &userCert, vector<X509Certificate> certificateChain)
{
    return X509Certificate_p::verify(userCert, certificateChain);
}

vector<X509Certificate> X509Certificate::systemCaCertificates()
{
    return X509Certificate_p::systemCaCertificates();
}

/*******************************************************Certificate Extension***********************************************************************/

X509CertificateExtension::X509CertificateExtension()
{

}

bool X509CertificateExtension::isCritical() const
{
    return p->m_critical;
}

bool X509CertificateExtension::isSupported() const
{
    return false;
}

string X509CertificateExtension::name() const
{
    return p->m_name;
}

string X509CertificateExtension::oid() const
{
    return p->m_oid;
}

string X509CertificateExtension::value() const
{
    return p->m_value;
}

X509CertificateExtension::ExtMethod X509CertificateExtension::methodType() const
{
    auto extMethod = Ext_String;
    if(p->m_method == X509CertificateExtension_p::Me_Vector) {
        extMethod = Ext_Vector;
    }
    else if(p->m_method == X509CertificateExtension_p::Me_Map) {
        extMethod = Ext_Map;
    }
    return extMethod;
}

string X509CertificateExtension::toString() const
{
    return p->m_i2sString;
}

vector<string> X509CertificateExtension::toVector() const
{
    return p->m_i2vVec;
}

multimap<string, string> X509CertificateExtension::toMap() const
{
    return p->m_i2vMap;
}
