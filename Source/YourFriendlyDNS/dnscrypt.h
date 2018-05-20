#ifndef DNSCRYPT_H
#define DNSCRYPT_H

#include <QHostAddress>
#include <QHostInfo>
#include <QSslSocket>
#include <QUdpSocket>
#include <QTcpSocket>
#include <QtEndian>
#include <QDateTime>
extern "C"{
#include <sodium.h>
}
#include "dnsinfo.h"
#include "buffer.h"

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
    DNSCryptProvider(QByteArray sdns, QObject *parent = nullptr)
    {
        Q_UNUSED(parent);

        if(sdns.size() > 7 && memcmp(sdns.data(), "sdns://", 7) == 0)
        {
            //Valid dnscrypt stamp so far...
            qDebug() << sdns;
            sdns.remove(0, 7);

            quint16 port2 = 0;
            quint8 hashLen;
            QByteArray hash;
            QByteArray unbased = QByteArray::fromBase64(sdns, QByteArray::Base64UrlEncoding);

            //Got to interpret it differently based on the protocol version though
            ModernBuffer buffer(unbased);
            buffer.unpack("BI", &protocolVersion, &props);
            switch(protocolVersion)
            {
            case 0:
                buffer.unpack("z", &addr);
                qDebug() << "Protocol version 0x0000 read -> Plain DNS! You should enter it in the app plainly too, addr:" << addr << "props:" << props;
                return;

            case 1:
                buffer.unpack("zzz", &addr, &providerPubKey, &providerName);
                qDebug() << "Protocol version 0x0001 read -> DNSCrypt!";
                qDebug() << "Provider name:" << providerName << "ProviderPubKey:" << providerPubKey << "props:" << props;

                if(providerPubKey.size() != crypto_box_PUBLICKEYBYTES)
                {
                    qDebug() << "PubKey length isn't right! Invalid stamp!";
                    return;
                }
                break;

            case 2:
                buffer.unpack("zB", &addr, &hashLen);
                while(hashLen & 0x80)
                {
                    hashLen &= ~0x80;
                    buffer.unpack(QString("[%1]").arg(hashLen).toStdString().c_str(), &hash);
                    hashes.append(hash);
                    qDebug() << "hash:" << hash << "hashLen:" << hashLen;
                    buffer.unpack("B", &hashLen);
                }
                buffer.unpack(QString("[%1]").arg(hashLen).toStdString().c_str(), &hash);
                hashes.append(hash);
                qDebug() << "hash:" << hash << "hashLen:" << hashLen;

                buffer.unpack("zz", &hostname, &path);
                port2 = DNSInfo::extractPort(hostname);
                qDebug() << "Protocol version 0x0002 read -> DNS over HTTPS!";
                qDebug() << "Host:" << hostname << "Path:" << path;
                break;

            case 3:
                buffer.unpack("zB", &addr, &hashLen);
                while(hashLen & 0x80)
                {
                    hashLen &= ~0x80;
                    buffer.unpack(QString("[%1]").arg(hashLen).toStdString().c_str(), &hash);
                    hashes.append(hash);
                    buffer.unpack("B", &hashLen);
                }
                buffer.unpack(QString("[%1]").arg(hashLen).toStdString().c_str(), &hash);
                hashes.append(hash);

                buffer.unpack("z", &hostname);
                port2 = DNSInfo::extractPort(hostname);
                qDebug() << "Protocol version 0x0003 read -> DNS over TLS!";
                qDebug() << "Host:" << hostname;
                break;

            default:
                qDebug() << "Unknown and unsupported protocol version...";
                break;
            }

            props = qToBigEndian(props);
            if(props & 1) qDebug() << "Provider supports DNSSEC";
            if(props & 2) qDebug() << "Provider doesn't keep logs";
            if(props & 4) qDebug() << "Provider doesn't intentionally block domains";

            port = DNSInfo::extractPort(addr);
            if(port == 443 && port2 != 0) port = port2;
            qDebug() << "Provider using address:" << addr << "and port:" << port;
        }
    }
    quint8 protocolVersion;
    quint16 port;
    quint64 props;
    QString providerName, hostname, path, addr;
    QByteArray providerPubKey;
    QVector<QByteArray> hashes;
};

class DoTLSResponse : public QObject
{
    Q_OBJECT
public:
    explicit DoTLSResponse(DNSInfo &dns, QObject *parent = nullptr);

    DNSInfo respondTo;
    QSslSocket tls;

signals:
    void decryptedLookupDoneSendResponseNow(QByteArray response, DNSInfo &dns);

public slots:
    void verifyError(const QSslError error);
    void disconnected();
    void startEncryption();
    void writeEncryptedDoTLS();
    void getAndDecryptResponseDoTLS();
};

class DoHResponse : public QObject
{
    Q_OBJECT
public:
    explicit DoHResponse(DNSInfo &dns, QByteArray dohRequest, QObject *parent = nullptr);

    DNSInfo respondTo;
    QByteArray request;
    QSslSocket tls;

signals:
    void decryptedLookupDoneSendResponseNow(QByteArray response, DNSInfo &dns);

public slots:
    void verifyError(const QSslError error);
    void disconnected();
    void startEncryption();
    void writeEncryptedDoH();
    void getAndDecryptResponseDoH();
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

private:
    void endResponse();
    DNSInfo respondTo;
    QByteArray encRequest;
    bool responseHandled;
    quint8 sk[crypto_box_SECRETKEYBYTES];

signals:
    void decryptedLookupDoneSendResponseNow(QByteArray response, DNSInfo &dns);
    void resendUsingTCP(DNSInfo &dns, QByteArray encryptedRequest, SignedBincertFields signedBincertFields, QString providername, quint8 *nonce, quint8 *sk);

public slots:
    void socketError(QAbstractSocket::SocketError error);
    void writeEncryptedRequestTCP();
    void getAndDecryptResponseTCP();
    void getAndDecryptResponse();
};

class CertificateHolder : public QObject
{
    Q_OBJECT
public:
    explicit CertificateHolder(DNSInfo &dns, QString providername, QHostAddress server, quint16 port, QObject *parent = nullptr);
    void addPadding(QByteArray &msg);
    SignedBincertFields bincertFields;
    QString providerName;
    QHostAddress certServer;
    quint16 serverPort;
    quint64 nextRotateKeyTime;

private:
    DNSInfo respondTo;
    bool usingTCP;

    quint8 pk[crypto_box_PUBLICKEYBYTES];
    quint8 sk[crypto_box_SECRETKEYBYTES];

signals:
    void decryptedLookupDoneSendResponseNow(QByteArray response, DNSInfo &dns);
    void deleteOldCertificatesForProvider(QString provider, QHostAddress server, SignedBincertFields newestCert);

public slots:
    void certificateVerifiedDoEncryptedLookup(SignedBincertFields bincertFields, QHostAddress serverAddress, quint16 serverPort, bool newKey = false, DNSInfo dns = DNSInfo());
    void resendUsingTCP(DNSInfo &dns, QByteArray encryptedRequest, SignedBincertFields signedBincertFields, QString providername, quint8 *nonce, quint8 *sk);
};

class DNSCrypt : public QObject
{
    Q_OBJECT
public:
    explicit DNSCrypt(QObject *parent = nullptr);
    void buildTXTRecord(QByteArray &txt);
    void getValidServerCertificate(DNSInfo &dns);
    CertificateHolder* getCachedCert(QHostAddress server, QString provider);
    void sendDoH(DNSInfo &dns);
    void sendDoTLS(DNSInfo &dns);
    void makeEncryptedRequest(DNSInfo &dns);
    void setProvider(QString dnscryptStamp);
    quint64 getTimeNow();

    QSslSocket tls;
    QUdpSocket udp;
    QByteArray request;
    QString providerName, hostname, path, currentStamp, userAgent;
    quint8 providerKey[crypto_box_PUBLICKEYBYTES];
    quint8 resolverMagic[DNSCRYPT_MAGIC_QUERY_LEN];
    quint8 protocolVersion;
    quint16 currentPort;
    QHostAddress currentServer;
    bool dnsCryptAvailable, dnsCryptEnabled, newKeyPerRequest, pendingValidation;
    SignedBincertFields currentCert;
    QVector<CertificateHolder*> certCache;

signals:
    void certificateVerifiedDoEncryptedLookup(SignedBincertFields bincertFields, QHostAddress serverAddress, quint16 serverPort, bool newKey = false, DNSInfo dns = DNSInfo());
    void decryptedLookupDoneSendResponseNow(QByteArray response, DNSInfo &dns);
    void displayLastUsedProvider(quint64 props, QString providerName, QHostAddress server, quint16 port);

public slots:
    void validateCertificates();
    void deleteOldCertificatesForProvider(QString provider, QHostAddress server, SignedBincertFields newestCert);
};



#endif // DNSCRYPT_H
