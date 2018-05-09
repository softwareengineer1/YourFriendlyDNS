#ifndef DNSCRYPT_H
#define DNSCRYPT_H

#include <QHostAddress>
#include <QUdpSocket>
#include <QTcpSocket>
#include <QtEndian>
#include <QDateTime>
extern "C"{
#include <sodium.h>
}
#include "dnsinfo.h"

//Constants and structs borrowed and slightly modified from DNSCrypt proxy C version
//Credit to jedisct1 and whoever else worked on it
//Also looking at willnix's basic dnscrypt client helped a lot (despite being written in go, and jedisct1's new go version too)
//And the protocol specification found here: https://github.com/dyne/dnscrypt-proxy/blob/master/DNSCRYPT-V2-PROTOCOL.txt
//<--
#define DNSCRYPT_MAGIC_QUERY_LEN 8U
#define DNSCRYPT_MAGIC_RESPONSE  "r6fnvWj8"
#define DNSCRYPT_MAXSIZE_UDP 65536 - 20 - 8

#ifndef DNSCRYPT_MAX_PADDING
# define DNSCRYPT_MAX_PADDING 256U
#endif
#ifndef DNSCRYPT_BLOCK_SIZE
# define DNSCRYPT_BLOCK_SIZE 64U
#endif
#ifndef DNSCRYPT_MIN_PAD_LEN
# define DNSCRYPT_MIN_PAD_LEN 8U
#endif
#define crypto_box_HALF_NONCEBYTES (crypto_box_NONCEBYTES / 2U)

#define CERT_MAGIC_LEN 4U
#define CERT_MAGIC_CERT "DNSC"

// SignedBincertFields Represents the detailed structure of a DNSC certificate
typedef struct SignedBincertFields_ {
    quint8 server_publickey[crypto_box_PUBLICKEYBYTES];
    quint8 magic_query[8];
    quint32 serial;
    quint32 ts_begin;
    quint32 ts_end;
} SignedBincertFields;

// SignedBincert Represents the structure of a DNSC certificate as needed to verify the signature
typedef struct SignedBincert_ {
    quint8 magic_cert[4];
    quint16 version_major;
    quint16 version_minor;
    quint8 signature[crypto_sign_BYTES];
    quint8 signed_data[52];
} SignedBincert;

// DNSCryptQueryHeader represents the header of a DNSC encrypted query
typedef struct dnsCryptQueryHeader_ {
    quint8 ClientMagic[DNSCRYPT_MAGIC_QUERY_LEN];
    quint8 ClientPublicKey[crypto_box_PUBLICKEYBYTES];
    quint8 ClientNonce[crypto_box_HALF_NONCEBYTES];
} dnsCryptQueryHeader;

// DNSCryptQueryHeader represents the header of a DNSC encrypted reply
typedef struct dnsCryptResponseHeader{
    quint8 ServerMagic[DNSCRYPT_MAGIC_QUERY_LEN];
    quint8 ClientNonce[crypto_box_HALF_NONCEBYTES];
    quint8 ServerNonce[crypto_box_HALF_NONCEBYTES];
} dnsCryptResponseHeader;

//<--

class DNSCryptProvider : public QObject
{
    Q_OBJECT
public:
    explicit DNSCryptProvider(QObject *parent = nullptr) { Q_UNUSED(parent); memset(providerPubKey, 0, sizeof providerPubKey); protocolVersion = 0; port = 0; props = 0; }
    DNSCryptProvider(QByteArray sdns, QObject *parent = nullptr)
    {
        Q_UNUSED(parent);

        if(sdns.size() > 4 && memcmp(sdns.data(), "sdns://", 7) == 0)
        {
            //Valid dnscrypt stamp so far...
            sdns.remove(0, 7);
            asBase64 = sdns;

            QByteArray unbased = QByteArray::fromBase64(sdns, QByteArray::Base64UrlEncoding);
            char *ptr = &unbased.data()[0], *ptr_end = &unbased.data()[unbased.size()];

            protocolVersion = *ptr++;
            if(protocolVersion == 1) qDebug() << "Protocol version 0x0001 read -> DNSCrypt!";
            else if(protocolVersion == 2) qDebug() << "Protocol verison 0x0002 read -> DoH";

            if(ptr >= ptr_end) return;

            props = *(quint64*)ptr; ptr += 8;

            if(props & 1) qDebug() << "Provider supports DNSSEC";
            if(props & 2) qDebug() << "Provider doesn't keep logs";
            if(props & 4) qDebug() << "Provider doesn't intentionally block domains";

            if(ptr >= ptr_end) return;

            quint8 addrLen = *ptr++;
            char addr[addrLen + 1];

            if((ptr + addrLen) >= ptr_end) return;

            memcpy(addr, ptr, addrLen);
            addr[addrLen] = 0;

            if(addr[0] == '[')
            {
                ipv6Address = addr;
                int portOffset = ipv6Address.lastIndexOf("]:");
                if(portOffset != -1)
                {
                    QString ipv6Port = ipv6Address.right(portOffset + 2);
                    qDebug() << "ipv6Port:" << ipv6Port;
                    ipv4Address.truncate(portOffset + 1);
                    port = ipv6Port.toInt();
                }
                else
                    port = 443;
            }
            else
            {
                ipv4Address = addr;
                int portOffset = ipv6Address.lastIndexOf(":");
                if(portOffset != -1)
                {
                    QString ipv4Port = ipv4Address.right(portOffset + 1);
                    qDebug() << "ipv4Port:" << ipv4Port;
                    ipv4Address.truncate(portOffset);
                    port = ipv4Port.toInt();
                }
                else
                    port = 443;

                isIPv4 = true;
                qDebug() << "Provider using IPv4 address:" << ipv4Address;
            }

            ptr += addrLen;
            quint8 pkLen = *ptr++;
            if(pkLen != crypto_box_PUBLICKEYBYTES)
            {
                qDebug() << "PubKey length isn't right! Invalid stamp!";
                return;
            }

            if((ptr + pkLen) >= ptr_end) return;

            memcpy(providerPubKey, ptr, pkLen);
            ptr += pkLen;
            qDebug() << "Provider PubKey aquired... len:" << pkLen;

            quint8 nameLen = *ptr++;
            char name[nameLen + 1];

            if((ptr + nameLen) > ptr_end) return;

            memcpy(name, ptr, nameLen);
            name[nameLen] = 0;

            providerName = name;
            qDebug() << "Provider name:" << providerName << "len:" << nameLen;
        }
    }

    quint8 providerPubKey[crypto_box_PUBLICKEYBYTES];
    quint8 protocolVersion;
    quint16 port;
    quint64 props;
    QString providerName, ipv4Address, ipv6Address;
    QByteArray asBase64;
    bool isIPv4;
};

class EncryptedResponse : public QObject
{
    Q_OBJECT
public:
    explicit EncryptedResponse(DNSInfo &dns, QByteArray encryptedRequest, SignedBincertFields signedBincertFields, QString providername, quint8 *nonce, quint8 *sk, QObject *parent = nullptr);
    void removePadding(QByteArray &msg);
    QUdpSocket udp;
    QTcpSocket tcp;
    SignedBincertFields bincertFields;
    QString providerName;
    quint8 nonce[crypto_box_NONCEBYTES];
    quint8 sk[crypto_box_SECRETKEYBYTES];

private:
    void endResponse();
    DNSInfo respondTo;
    QByteArray encRequest;
    bool responseHandled;

signals:
    void decryptedLookupDoneSendResponseNow(QByteArray response, DNSInfo &dns);
    void switchToTCP();

public slots:
    void writeEncryptedRequestTCP();
    void getAndDecryptResponseTCP();
    void getAndDecryptResponse();
};

class CertificateResponse : public QObject
{
    Q_OBJECT
public:
    explicit CertificateResponse(DNSInfo &dns, QString providername, QObject *parent = nullptr);
    void addPadding(QByteArray &msg);
    SignedBincertFields bincertFields;
    QString providerName;

private:
    DNSInfo respondTo;
    bool usingTCP, newKeyPerRequest;
    quint8 pk[crypto_box_PUBLICKEYBYTES];
    quint8 sk[crypto_box_SECRETKEYBYTES];

signals:
    void decryptedLookupDoneSendResponseNow(QByteArray response, DNSInfo &dns);
    void deleteOldCertificatesForProvider(QString provider, SignedBincertFields newestCert);

public slots:
    void certificateVerifiedDoEncryptedLookup(SignedBincertFields bincertFields, QHostAddress serverAddress, quint16 serverPort, DNSInfo dns = DNSInfo());
};

class DNSCrypt : public QObject
{
    Q_OBJECT
public:
    explicit DNSCrypt(QObject *parent = nullptr);
    void buildTXTRecord(QByteArray &txt);
    void getValidServerCertificate(DNSInfo &dns);
    void makeEncryptedRequest(DNSInfo &dns);
    void setProvider(QString dnscryptStamp);

    QUdpSocket udp;
    QString providerName, currentStamp;
    quint8 providerKey[crypto_box_PUBLICKEYBYTES];
    quint8 resolverMagic[DNSCRYPT_MAGIC_QUERY_LEN];
    quint16 currentPort;
    QHostAddress currentServer;
    bool dnsCryptAvailable, dnsCryptEnabled, gotValidCert, providerSet, changedProviders;
    SignedBincertFields currentCert, lastCertUsed;
    QVector<CertificateResponse*> certCache;

signals:
    void certificateVerifiedDoEncryptedLookup(SignedBincertFields bincertFields, QHostAddress serverAddress, quint16 serverPort, DNSInfo dns = DNSInfo());
    void decryptedLookupDoneSendResponseNow(QByteArray response, DNSInfo &dns);

public slots:
    void validateCertificates();
    void decryptedLookupDoneSendResponseNow2(const QByteArray &response, DNSInfo &dns);
    void deleteOldCertificatesForProvider(QString provider, SignedBincertFields newestCert);
};



#endif // DNSCRYPT_H
