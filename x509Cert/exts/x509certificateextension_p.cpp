#include "x509certificateextension_p.h"

X509CertificateExtension_p::X509CertificateExtension_p()
{

}

X509CertificateExtension_p &X509CertificateExtension_p::operator=(const X509CertificateExtension_p &other)
{
    this->m_oid = other.m_oid;
    this->m_name = other.m_name;
    this->m_value = other.m_value;
    this->m_critical = other.m_critical;
    this->m_method = other.m_method;
    this->m_i2sString = other.m_i2sString;
    this->m_i2vVec = other.m_i2vVec;
    this->m_i2vMap = other.m_i2vMap;
    return *this;
}
