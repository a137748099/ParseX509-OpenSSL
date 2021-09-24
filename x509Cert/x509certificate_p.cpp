#include "x509certificate_p.h"
#include "x509certificate.h"
#include "exts/x509certificateextension_p.h"
#include <assert.h>
#include <utility>
#include <string.h>
#include <memory>
#include <time.h>
#include <set>
#include <iostream>
#ifdef WIN32
#include <windows.h>
#include <wincrypt.h>
#undef X509_NAME//conflict
#include <cryptuiapi.h>
#include <tchar.h>
#endif

#ifdef linux
#include <dirent.h>
#endif

#ifdef  __cplusplus
extern "C" {
#endif
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/pkcs7.h>
#include <openssl/bio.h>
#include <openssl/conf.h>
#ifdef  __cplusplus
}
#endif

#ifdef WIN32
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "cryptui.lib")
#endif

#define X509Assert assert(m_pX509 != 0)
#define SKM_sk_num(type, st) ((int (*)(const STACK_OF(type) *))sk_num)(st)
#define SKM_sk_value(type, st,i) ((type * (*)(const STACK_OF(type) *, int))sk_value)(st, i)

#define BEGINCERTSTRING "-----BEGIN CERTIFICATE-----"
#define ENDCERTSTRING "-----END CERTIFICATE-----"

std::map<string,string> _subject_as_map(X509_NAME *subj_or_issuer);

X509Certificate_p::X509Certificate_p(const char *cert, int len):
    m_pX509(initX509(cert, len))
{
    subjectMap = _subject_as_map(X509_get_subject_name(m_pX509));
    issuerMap = _subject_as_map(X509_get_issuer_name(m_pX509));
}

X509Certificate_p::~X509Certificate_p()
{
    for(auto certExt : m_certExtVec) {
        delete certExt;
        certExt = nullptr;
    }
    m_certExtVec.clear();
    m_bExtInit = false;
}

int X509Certificate_p::version() const
{
    X509Assert;
    return X509_get_version(m_pX509);
}

string X509Certificate_p::serialNumber() const
{
    X509Assert;
    std::string serialNam;
    ASN1_INTEGER *asniData = X509_get_serialNumber(m_pX509);
    BIGNUM *bigNum = ASN1_INTEGER_to_BN(asniData, nullptr);
    if(!bigNum)
        return serialNam;

    char *hexData = BN_bn2hex(bigNum);
    if(!hexData)
        return serialNam;

    serialNam = std::string(hexData);
    BN_free(bigNum);
    OPENSSL_free(hexData);
    return serialNam;
}

string X509Certificate_p::subject() const
{
    X509Assert;
    string subStr;
    char *subj = X509_NAME_oneline(X509_get_subject_name(m_pX509), nullptr, 0);
    if(subj) {
        subStr = string(subj);
    }
    return subStr;
}

string X509Certificate_p::subjectInfo(string dnKey)
{
    return subjectMap[dnKey];
}

string X509Certificate_p::issuer() const
{
    X509Assert;
    string issuerStr;
    char *issuer = X509_NAME_oneline(X509_get_issuer_name(m_pX509), nullptr, 0);
    if(issuer) {
        issuerStr = string(issuer);
    }
    return issuerStr;
}

string X509Certificate_p::issuerInfor(string dnKey)
{
    return issuerMap[dnKey];
}

static int mypint( const char ** s, int n, int min, int max, int * e)
{
    int retval = 0;
    while (n) {
        if (**s < '0' || **s > '9') { *e = 1; return 0; }
        retval *= 10;
        retval += **s - '0';
        --n; ++(*s);
    }
    if (retval < min || retval > max) *e = 1;
    return retval;
}

static time_t ASN1_TIME_get ( ASN1_TIME * a, int *err)
{
    char days[2][12] ={{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },
                { 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }};
    int dummy;
    const char *s;
    int generalized;
    struct tm t;
    int i, year, isleap, offset;
    time_t retval;
    if (err == NULL)
        err = &dummy;
    if (a->type == V_ASN1_GENERALIZEDTIME) {
        generalized = 1;
    } else if (a->type == V_ASN1_UTCTIME) {
        generalized = 0;
    } else {
        *err = 1;
        return 0;
    }
    s = (char *)a->data; // Data should be always null terminated
    if (s == NULL || s[a->length] != '\0') {
        *err = 1;
        return 0;
    }
    *err = 0;
    if (generalized) {
        t.tm_year = mypint(&s, 4, 0, 9999, err) - 1900;
    } else {
        t.tm_year = mypint(&s, 2, 0, 99, err);
    if (t.tm_year < 50)
        t.tm_year += 100;
    }
    t.tm_mon = mypint(&s, 2, 1, 12, err) - 1;
    t.tm_mday = mypint(&s, 2, 1, 31, err);
// NOTE: It's not yet clear, if this implementation is 100% correct
// for GeneralizedTime... but at least misinterpretation is
// impossible --- we just throw an exception
    t.tm_hour = mypint(&s, 2, 0, 23, err);
    t.tm_min = mypint(&s, 2, 0, 59, err);
    if (*s >= '0' && *s <= '9') {
        t.tm_sec = mypint(&s, 2, 0, 59, err);
    } else {
        t.tm_sec = 0;
    }
    if (*err)
        return 0; // Format violation
    if (generalized) {
        // skip fractional seconds if any
        while (*s == '.' || *s == ',' || (*s >= '0' && *s <= '9')) ++s;
        // special treatment for local time
        if (*s == 0) {
            t.tm_isdst = -1;
            retval = mktime(&t); // Local time is easy :)
            if (retval == (time_t)-1) {
                *err = 2;
                retval = 0;
            }
            return retval;
        }
    }
    if (*s == 'Z') {
        offset = 0;
        ++s;
    } else if (*s == '-' || *s == '+') {
        i = (*s++ == '-');
        offset = mypint(&s, 2, 0, 12, err);
        offset *= 60;
        offset += mypint(&s, 2, 0, 59, err);
        if (*err) return 0; // Format violation
        if (i) offset = -offset;
        } else {
        *err = 1;
        return 0;
    }
    if (*s) {
        *err = 1;
        return 0;
    }
// And here comes the hard part --- there's no standard function to
// convert struct tm containing UTC time into time_t without
// messing global timezone settings (breaks multithreading and may
// cause other problems) and thus we have to do this "by hand"
//
// NOTE: Overflow check does not detect too big overflows, but is
// sufficient thanks to the fact that year numbers are limited to four
// digit non-negative values.
    retval = t.tm_sec;
    retval += (t.tm_min - offset) * 60;
    retval += t.tm_hour * 3600;
    retval += (t.tm_mday - 1) * 86400;
    year = t.tm_year + 1900;
    if ( sizeof (time_t) == 4) {
        // This is just to avoid too big overflows being undetected, finer
        // overflow detection is done below.
        if (year < 1900 || year > 2040) *err = 2;
    }
// FIXME: Does POSIX really say, that all years divisible by 4 are
// leap years (for consistency)??? Fortunately, this problem does
// not exist for 32-bit time_t and we should'nt be worried about
// this until the year of 2100 :)
    isleap = ((year % 4 == 0) && (year % 100 != 0)) || (year % 400 == 0);
    for (i = t.tm_mon - 1; i >= 0; --i) retval += days[isleap][i] * 86400;
    retval += (year - 1970) * 31536000;
    if (year < 1970) {
        retval -= ((1970 - year + 2) / 4) * 86400;
        if ( sizeof (time_t) > 4) {
            for (i = 1900; i >= year; i -= 100) {
                if (i % 400 == 0) continue ;
                retval += 86400;
            }
        }
        if (retval >= 0) *err = 2;
    } else {
        retval += ((year - 1970 + 1) / 4) * 86400;
        if ( sizeof (time_t) > 4) {
            for (i = 2100; i < year; i += 100) {
                // The following condition is the reason to
                // start with 2100 instead of 2000
                if (i % 400 == 0) continue ;
                retval -= 86400;
            }
        }
        if (retval < 0) *err = 2;
    }
    if (*err) retval = 0;
    return retval;
}

string X509Certificate_p::notBefor() const
{
    X509Assert;
    ASN1_TIME *not_before = X509_get_notBefore(m_pX509);
    int rc;
    time_t time = ASN1_TIME_get(not_before, &rc);
    char str_time[100];
    struct tm tm_1;
#ifdef WIN32
    localtime_s(&tm_1, &time);
#else
    localtime_r(&time, &tm_1);
#endif
    strftime(str_time, sizeof(str_time), "%Y-%m-%d %H:%M:%S", &tm_1);

    std::string notBeforStr(str_time);
    return notBeforStr;
}

string X509Certificate_p::notAfter() const
{
    X509Assert;
    ASN1_TIME *not_after = X509_get_notAfter(m_pX509);
    int rc;
    time_t time = ASN1_TIME_get(not_after, &rc);
    char str_time[100];
    struct tm tm_1;
#ifdef WIN32
    localtime_s(&tm_1, &time);
#else
    localtime_r(&time, &tm_1);
#endif
    strftime(str_time, sizeof(str_time), "%Y-%m-%d %H:%M:%S", &tm_1);
    std::string notAfterStr(str_time);
    return notAfterStr;
}

static void hex_encode(unsigned char* readbuf, void *writebuf, size_t len)
{
    for(size_t i=0; i < len; i++) {
        char *l = (char*) (2*i + ((intptr_t) writebuf));
        sprintf(l, "%02x", readbuf[i]);
    }
}

string X509Certificate_p::publicKeyValue() const
{
    X509Assert;
    EVP_PKEY *pubKey = X509_get_pubkey(m_pX509);
    unsigned char *spki = nullptr;
    int len = i2d_PUBKEY(pubKey, &spki);
    if(len < 0)
        return "";

    char *buf = new char[len*2 + 1];
    memset(buf, 0, len*2 + 1);
    hex_encode(spki, buf, len);
    EVP_PKEY_free(pubKey);
    std::string pubStr(buf, len*2 + 1);
    free(buf);
    return pubStr;
}

string X509Certificate_p::publicKeyType() const
{
    X509Assert;
    EVP_PKEY *pubKey = X509_get_pubkey(m_pX509);
    int bits = EVP_PKEY_bits(pubKey);

    int id = EVP_PKEY_base_id(pubKey);
    char buf[20] = {0};
    switch (id) {
    case EVP_PKEY_RSA:
        sprintf(buf, "RSA(%d Bits)", bits);
        break;
    case EVP_PKEY_DSA:
        sprintf(buf, "DSA(%d Bits)", bits);
        break;
    case EVP_PKEY_DH:
        sprintf(buf, "DH(%d Bits)", bits);
        break;
    case EVP_PKEY_EC:
        sprintf(buf, "ECC(%d Bits)", bits);
        break;
    default:
        break;
    }

    return string(buf);
}

string X509Certificate_p::signAlgType() const
{
    X509Assert;
    string sigAlg;
    const X509_ALGOR *alg = X509_get0_tbs_sigalg(m_pX509);
    if(alg->parameter) {
        int sig_nid = OBJ_obj2nid(alg->algorithm);
        if(sig_nid != NID_undef) {
            sigAlg = string(OBJ_nid2ln(sig_nid));
        }
    }
    else {//SM2
        char test[32] = {0};
        int len = OBJ_obj2txt(test, 32, alg->algorithm, 0);
        string oid(test, len);
        if(oid == "1.2.156.10197.1.501") {
            sigAlg = "SM3WithSM2Encryption";
        }
        else if(oid == "1.2.840.113549.1.1.5") {
            sigAlg = "sha1WithRSAEncryption";
        }
        else if(oid == "1.2.840.113549.1.1.11") {
            sigAlg = "sha256WithRSAEncryption";
        }
    }

    return sigAlg;
}

string X509Certificate_p::signValue() const
{
    X509Assert;
    const ASN1_BIT_STRING *psig = nullptr;
    X509_get0_signature(&psig, nullptr, m_pX509);
    int len = psig->length;
    char *buf = new char[len*2 + 1];
    memset(buf, 0, len*2 + 1);
    hex_encode(psig->data, buf, len);
    std::string sigVal(buf, len);
    return sigVal;
}

string X509Certificate_p::digest(string type) const
{
    X509Assert;
    string digestValue;

    const EVP_MD *digest = nullptr;
    int hashLen = 0;
    if(type == "Sha1") {
        hashLen = 20;
        digest = EVP_sha1();
    }
    else if(type == "Sha256") {
        hashLen = 32;
        digest = EVP_sha256();
    }
    else if(type == "SM3") {
        hashLen = 32;
        digest = EVP_sm3();
    }
    else {
        return digestValue;
    }
    unsigned char *buf = new unsigned char[hashLen + 1];
    memset(buf, 0, hashLen + 1);

    unsigned len;
    int rc = X509_digest(m_pX509, digest, buf, &len);
    if (rc == 0 || len != hashLen) {
        return "";
    }

    char *strbuf = new char[2*hashLen+1];
    memset(strbuf, 0, 2*hashLen+1);
//    char strbuf[2*hashLen+1];
    hex_encode(buf, strbuf, hashLen);

    digestValue = string(strbuf, 2*hashLen+1);
    delete [] buf;
    delete [] strbuf;
    return digestValue;
}

vector<X509CertificateExtension_p *> X509Certificate_p::extensions()
{
    if(m_bExtInit) {
        return m_certExtVec;
    }

    X509Assert;
    const STACK_OF(X509_EXTENSION) *exts = X509_get0_extensions(m_pX509);

    int num_of_exts;
    if (exts) {
        num_of_exts = sk_X509_EXTENSION_num(exts);
    } else {
        num_of_exts = 0;
    }

    for (int i = 0; i < num_of_exts; i++) {

        X509_EXTENSION *ex = sk_X509_EXTENSION_value(exts, i);
        ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);

        BIO *ext_bio = BIO_new(BIO_s_mem());
        if (!X509V3_EXT_print(ext_bio, ex, 0, 0)) {
//            printf()
        }

        BUF_MEM *bptr;
        BIO_get_mem_ptr(ext_bio, &bptr);
        BIO_set_close(ext_bio, BIO_NOCLOSE);

        // remove newlines
        int lastchar = bptr->length;
        if (lastchar > 1 && (bptr->data[lastchar-1] == '\n' || bptr->data[lastchar-1] == '\r')) {
            bptr->data[lastchar-1] = (char) 0;
        }
        if (lastchar > 0 && (bptr->data[lastchar] == '\n' || bptr->data[lastchar] == '\r')) {
            bptr->data[lastchar] = (char) 0;
        }

        X509CertificateExtension_p *certExt = new X509CertificateExtension_p;

        certExt->m_critical = X509_EXTENSION_get_critical(ex) == 1 ? true : false;

        char extname[1024];
        OBJ_obj2txt(extname, 1024, (const ASN1_OBJECT *) obj, 1);
        certExt->m_oid = string(extname);

        unsigned nid = OBJ_obj2nid(obj);
        if (nid != NID_undef) {
            const char *c_ext_name = OBJ_nid2sn(nid);
            certExt->m_name = string(c_ext_name);
        }
        certExt->m_value = string(bptr->data, bptr->length);
        m_certExtVec.push_back(certExt);

        BIO_free(ext_bio);

        //获取具体的值
        X509V3_EXT_METHOD *meth = const_cast<X509V3_EXT_METHOD *>(X509V3_EXT_get(ex));
        if (!meth) {
            ASN1_OCTET_STRING *value = X509_EXTENSION_get_data(ex);
            string result( reinterpret_cast<const char *>(ASN1_STRING_get0_data(value)),
                               ASN1_STRING_length(value));
            certExt->m_method = X509CertificateExtension_p::Me_String;
            certExt->m_i2sString = result;
            continue;
        }

        void *ext_internal = X509V3_EXT_d2i(ex);

        if (meth->i2v && ext_internal) {
            STACK_OF(CONF_VALUE) *val = meth->i2v(meth, ext_internal, nullptr);

            multimap<string, string> map;
            vector<string> list;
            bool isMap = false;

            for (int j = 0; j < SKM_sk_num(CONF_VALUE, val); j++) {
                CONF_VALUE *nval = SKM_sk_value(CONF_VALUE, val, j);
                if (nval->name && nval->value) {
                    isMap = true;
                    map.insert(pair<string,string>(string(nval->name), string(nval->value)));
                }
                else if (nval->name) {
                    list.push_back(string(nval->name));
                }
                else if (nval->value) {
                    list.push_back(string(nval->value));
                }
            }

            if (isMap) {
                certExt->m_method = X509CertificateExtension_p::Me_Map;
                certExt->m_i2vMap = map;
            }
            else {
                certExt->m_method = X509CertificateExtension_p::Me_Vector;
                certExt->m_i2vVec = list;
            }
        }
        else if (meth->i2s && ext_internal) {
            string result(string(meth->i2s(meth, ext_internal)));
            certExt->m_method = X509CertificateExtension_p::Me_String;
            certExt->m_i2sString = result;
        }
        else if (meth->i2r && ext_internal) {
            string result;

            BIO *bio = BIO_new(BIO_s_mem());
            if (bio) {
                meth->i2r(meth, ext_internal, bio, 0);

                char *bio_buffer;
                long bio_size = BIO_get_mem_data(bio, &bio_buffer);
                result = string(bio_buffer, bio_size);
                certExt->m_method = X509CertificateExtension_p::Me_String;
                certExt->m_i2sString = result;
                BIO_free(bio);
            }
        }
    }

    m_bExtInit = true;
    return m_certExtVec;
}

std::string X509Certificate_p::toDer() const
{
    X509Assert;

    string derStr;
    unsigned char *buf = nullptr;
    int len = i2d_X509(m_pX509, &buf);
    if(len > 0) {
        derStr = string(reinterpret_cast<const char *>(buf), len);
    }

    return derStr;
}

std::string X509Certificate_p::toPem() const
{
    X509Assert;

    string pemStr;
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, m_pX509);
    if(!bio) {
        return pemStr;
    }

    BUF_MEM *bptr = NULL;
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bptr);
    pemStr = string(bptr->data, bptr->length);
    BIO_free(bio);

    return pemStr;
}

string X509Certificate_p::toText() const
{
    X509Assert;
    string certText;
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio)
        return certText;
    X509_print(bio, m_pX509);

    char buff[16384] = {0};
    int count = BIO_read(bio, buff, 16384);
    if ( count > 0 ) {
        certText = string( buff, count );
    }

    BIO_free(bio);

    return certText;
}

bool X509Certificate_p::importPkcs12(const char *pfxFile, int len, char *priKey, int &priKeyLen, X509Certificate *x509Cert, vector<X509Certificate> &caCerts, const char *pass)
{
    FILE *fp;
    EVP_PKEY *pkey;
    X509 *cert;
    STACK_OF(X509) *ca = NULL;
    PKCS12 *p12;
    int i;

    if(!x509Cert) {
        return false;
    }

    OpenSSL_add_all_algorithms();
    if(len == 0) {
        if (!(fp = fopen(pfxFile, "rb"))) {
            return false;
        }
        p12 = d2i_PKCS12_fp(fp, NULL);
        fclose (fp);
    }
    else {
        auto bio = BIO_new_mem_buf((void *)pfxFile, len);
        if(!bio) {
            return false;
        }
        p12 = d2i_PKCS12_bio(bio, NULL);
        BIO_free(bio);
    }

    if (!p12) {
        fprintf(stderr, "Error reading PKCS#12 file\n");
        return false;
    }
    if (!PKCS12_parse(p12, pass, &pkey, &cert, &ca)) {
        fprintf(stderr, "Error parsing PKCS#12 file\n");
        return false;
    }
    PKCS12_free(p12);

    if (pkey) {
        BIO *bio = BIO_new(BIO_s_mem());
        PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);
        BUF_MEM *bptr = NULL;
        BIO_flush(bio);
        BIO_get_mem_ptr(bio, &bptr);
        if(priKeyLen < bptr->length || priKey == nullptr) {
            return false;
        }
        memcpy(priKey, bptr->data, bptr->length);
        priKeyLen = bptr->length;

        BIO_free(bio);
    }

    if (cert) {
        unsigned char *buf = nullptr;
        int len = i2d_X509(cert, &buf);
        x509Cert->p = make_shared<X509Certificate_p>(reinterpret_cast<const char *>(buf), len);
    }

    for (i = 0; ca && i < sk_X509_num(ca); i++) {
        X509 *x = sk_X509_value(ca,i);
        unsigned char *buf = nullptr;
        int len = i2d_X509(x, &buf);
        if(len <= 0) {
            return false;
        }
//        X509Certificate *x509Cert = new X509Certificate(reinterpret_cast<const char *>(buf), len);
        X509Certificate x509Cert(reinterpret_cast<const char *>(buf), len);
        caCerts.push_back(x509Cert);
    }

    sk_X509_pop_free(ca, X509_free);
    X509_free(cert);
    EVP_PKEY_free(pkey);

    return true;
}

bool X509Certificate_p::importP7b(const char *p7b, int len, vector<X509Certificate> &caCerts, int format)
{
    PKCS7 *p7 = NULL;
    BIO *in = BIO_new(BIO_s_file());

    STACK_OF(X509) *certs = NULL;
    int i;

    OpenSSL_add_all_algorithms();

    if (len == 0) { //disk file
        in = BIO_new_file(p7b, "rb");
    }
    else { //memory file
        in = BIO_new_mem_buf((void *)p7b, len);
    }
    if(!in) {
        return false;
    }
    p7 = format ? d2i_PKCS7_bio(in, NULL) : PEM_read_bio_PKCS7(in, NULL, NULL, NULL);

    i = OBJ_obj2nid(p7->type);
    if(i == NID_pkcs7_signed) {
        certs = p7->d.sign->cert;
    } else if(i == NID_pkcs7_signedAndEnveloped) {
        certs = p7->d.signed_and_enveloped->cert;
    }

    for (i = 0; certs && i < sk_X509_num(certs); i++) {
        X509 *x = sk_X509_value(certs,i);
        unsigned char *buf = nullptr;
        int len = i2d_X509(x, &buf);
        if(len <= 0) {
            return false;
        }
//        X509Certificate *x509Cert = new X509Certificate(reinterpret_cast<const char *>(buf), len);
        X509Certificate x509Cert(reinterpret_cast<const char *>(buf), len);
        caCerts.push_back(x509Cert);
    }

    BIO_free(in);

    return true;
}

vector<X509Certificate> X509Certificate_p::splitCertChain(const string &chains)
{
    vector<X509Certificate> certsVec;
    string::size_type startPos = 0;
    string::size_type endPos = 0;
    string buff = chains;
    while (buff.size() > 0) {
        startPos = buff.find(BEGINCERTSTRING);
        endPos = buff.find(ENDCERTSTRING) + sizeof (ENDCERTSTRING);
        string tmp = buff.substr(startPos, endPos);
        buff = endPos >= buff.size() ? "" : buff.substr(endPos, buff.size());

        X509Certificate cert(tmp.c_str(), static_cast<int>(tmp.size()));
        certsVec.push_back(cert);
    }

    return certsVec;
}

int X509Certificate_p::verify(const X509Certificate &userCert, vector<X509Certificate> certificateChain)
{
    int ret = 0;
    X509_STORE *store;
    X509_STORE_CTX *ctx;

    store = X509_STORE_new();
    for(auto caCert : certificateChain) {
        X509_STORE_add_cert(store, reinterpret_cast<X509 *>(caCert.handle()));
    }

    ctx = X509_STORE_CTX_new();
    if(!ctx) {
        X509_STORE_free(store);
        return -1;
    }

    ret = X509_STORE_CTX_init(ctx, store, reinterpret_cast<X509 *>(userCert.handle()), NULL);
    if (ret != 1) {
//        ret = X509_STORE_CTX_get_error(ctx);
//        printf("err %d", ret);
        X509_STORE_free(store);
        X509_STORE_CTX_free(ctx);
        return -1;
    }

    ret = X509_verify_cert(ctx);

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);

    return ret;
}

#ifdef linux
static vector<string> GetFiles(const char *src_dir, const char *ext, const char *ext2)
{
    vector<string> result;
    string directory(src_dir);
    string m_ext(ext);
    string m_ext2(ext2);
    //printf("ext length:%d\n",m_ext.length());

    // 打开目录, DIR是类似目录句柄的东西
    DIR *dir = opendir(src_dir);
    if ( dir == NULL )
    {
        printf("[ERROR] %s is not a directory or not exist!", src_dir);
        return result;
    }

    // dirent会存储文件的各种属性
    struct dirent* d_ent = NULL;

    // linux每个目录下面都有一个"."和".."要把这两个都去掉
    char dot[3] = ".";
    char dotdot[6] = "..";

    // 一行一行的读目录下的东西,这个东西的属性放到dirent的变量中
    while ( (d_ent = readdir(dir)) != NULL )
    {
        // 忽略 "." 和 ".."
        if ( (strcmp(d_ent->d_name, dot) != 0) && (strcmp(d_ent->d_name, dotdot) != 0) )
        {
            // d_type可以看到当前的东西的类型,DT_DIR代表当前都到的是目录,在usr/include/dirent.h中定义的
            if ( d_ent->d_type != DT_DIR)
            {
                string d_name(d_ent->d_name);
                //printf("%s\n",d_ent->d_name);
                if (strcmp(d_name.c_str () + d_name.length () - m_ext.length(), m_ext.c_str ()) == 0 ||
                    strcmp(d_name.c_str () + d_name.length () - m_ext2.length(), m_ext2.c_str ()) == 0)
                {
                    // 构建绝对路径
                    string absolutePath = directory + string("/") + string(d_ent->d_name);
//                     如果传入的目录最后是/--> 例如"a/b/", 那么后面直接链接文件名
                    if (directory[directory.length()-1] == '/')
                        absolutePath = directory + string(d_ent->d_name);
                    result.push_back(absolutePath);
//                    result.push_back(string(d_ent->d_name));
                }
            }
        }
    }

    // sort the returned files
//    sort(result.begin(), result.end());

    closedir(dir);
    return result;
}
#endif

vector<X509Certificate> X509Certificate_p::systemCaCertificates()
{
    vector<X509Certificate> systemCerts;
#ifdef WIN32
    HCERTSTORE hSystemStore;
    hSystemStore = CertOpenSystemStoreW(0, L"ROOT");
    if (hSystemStore) {
        PCCERT_CONTEXT pc = nullptr;
        while (1) {
            pc = CertFindCertificateInStore(hSystemStore, X509_ASN_ENCODING, 0, CERT_FIND_ANY, nullptr, pc);
            if (!pc)
                break;

            X509Certificate cert(reinterpret_cast<const char *>(pc->pbCertEncoded), static_cast<int>(pc->cbCertEncoded));
            systemCerts.push_back(cert);
        }
        CertCloseStore(hSystemStore, 0);
    }
#else
    set<string> certFiles;
    vector<string> directories = {"/etc/ssl/certs/", // (K)ubuntu, OpenSUSE, Mandriva ...
                                  "/usr/lib/ssl/certs/", // Gentoo, Mandrake
                                  "/usr/share/ssl/", // Centos, Redhat, SuSE
                                  "/usr/local/ssl/", // Normal OpenSSL Tarball
                                  "/var/ssl/certs/", // AIX
                                  "/usr/local/ssl/certs/", // Solaris
                                  "/etc/openssl/certs/", // BlackBerry
                                  "/opt/openssl/certs/", // HP-UX
                                  "/etc/ssl/" // OpenBSD
    };

    for (size_t a = 0; a < directories.size(); a++) {
        auto certFileVec = GetFiles(directories.at(a).c_str(), ".pem", ".crt");

//        int index = 0;
        for(auto fileName : certFileVec) {
//            cout << index++ << ": " << fileName << endl;
            certFiles.insert(fileName);
        }
    }

//    int num = 0;
    for(auto fileName : certFiles) {
//        cout << num++ << ". " << "filename:" << fileName << endl;
        X509Certificate cert(fileName.c_str(), 0);
        systemCerts.push_back(cert);
    }
#endif
    return systemCerts;
}


X509 *X509Certificate_p::initX509(const char *cert, int len)
{
    X509 *xcert = nullptr;
    BIO* bio = Mem2Bio(cert, len);
    xcert = d2i_X509_bio(bio, NULL);
    if(!xcert) {
        //pem证书
        BIO* bio2 = Mem2Bio(cert, len);
        xcert = PEM_read_bio_X509(bio2, NULL, NULL, NULL);
        BIO_free(bio2);
        if (!xcert) {
            printf("cert parse failed");
            return nullptr;
        }
    }
    BIO_free(bio);

    return xcert;
}

BIO *X509Certificate_p::Mem2Bio(const char *lpBuf, const int nBufLen)
{
    BIO *bio = NULL;
    if (nBufLen == 0) { //disk file
        if ((bio = BIO_new_file(lpBuf, "rb")) == nullptr) {
            return nullptr;
        }
    }
    else { //memory file
        if ((bio = BIO_new_mem_buf((void *)lpBuf, nBufLen)) == nullptr) {
            return nullptr;
        }
    }

    return bio;
}

static string _asn1string(ASN1_STRING *d)
{
    string asn1_string;
    if (ASN1_STRING_type(d) != V_ASN1_UTF8STRING) {
        unsigned char *utf8;
        int length = ASN1_STRING_to_UTF8( &utf8, d );
        asn1_string= string( reinterpret_cast<char *>(utf8), length );
        OPENSSL_free( utf8 );
    } else {
        asn1_string= string( reinterpret_cast<char *>(ASN1_STRING_data(d)), ASN1_STRING_length(d) );
    }
    return asn1_string;
}

std::map<string,string> _subject_as_map(X509_NAME *subj_or_issuer)
{
    std::map<string,string> m;
    for (int i = 0; i < X509_NAME_entry_count(subj_or_issuer); i++) {
        X509_NAME_ENTRY *e = X509_NAME_get_entry(subj_or_issuer, i);
        ASN1_STRING *d = X509_NAME_ENTRY_get_data(e);
        ASN1_OBJECT *o = X509_NAME_ENTRY_get_object(e);
        const char* key_name = OBJ_nid2sn( OBJ_obj2nid( o ) );
                m[key_name] = _asn1string(d);
    }
    return m;
}
