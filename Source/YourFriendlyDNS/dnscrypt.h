#ifndef DNSCRYPT_H
#define DNSCRYPT_H

#include <QHostAddress>
#include <QSslSocket>
#include <QUdpSocket>
#include <QTcpSocket>
#include <QtEndian>
#include <QDateTime>
#include <QCryptographicHash>
#include <QStandardPaths>
#include <QFile>
#include <QDir>
extern "C"{
#include <sodium.h>
}
#include "dnsinfo.h"
#include "buffer.h"

/* YourFriendlyDNS - A really awesome multi-platform (lin,win,mac,android) local caching and proxying dns server!
Copyright (C) 2018  softwareengineer1 @ github.com/softwareengineer1
Support my work by sending me some Bitcoin or Bitcoin Cash in the value of what you valued one or more of my software projects,
so I can keep bringing you great free and open software and continue to do so for a long time!
I'm going entirely 100% free software this year in 2018 (and onwards I want to) :)
Everything I make will be released under a free software license! That's my promise!
If you want to contact me another way besides through github, insert your message into the blockchain with a BCH/BTC UTXO! ^_^
Thank you for your support!
BCH: bitcoincash:qzh3knl0xeyrzrxm5paenewsmkm8r4t76glzxmzpqs
BTC: 1279WngWQUTV56UcTvzVAnNdR3Z7qb6R8j
(These are the payment methods I currently accept,
if you want to support me via another cryptocurrency let me know and I'll probably start accepting that one too)

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA. */

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

enum class DNSCryptProtocol
{
    PlainDNS, DNSCrypt, DNSoverHTTPS, DNSoverTLS
};

class DNSCryptProvider : public QObject
{
    Q_OBJECT
public:
    DNSCryptProvider(QObject *parent = nullptr)
    {
        Q_UNUSED(parent);
        protocolVersion = 0;
        port = 0;
        props = 0;
    }
    DNSCryptProvider(QByteArray sdns, QObject *parent = nullptr)
    {
        Q_UNUSED(parent);

        if(sdns.size() > 7 && memcmp(sdns.data(), "sdns://", 7) == 0)
        {
            //Valid dnscrypt stamp so far...
            sdns.remove(0, 7);

            quint16 port2 = 0;
            QByteArray unbased = QByteArray::fromBase64(sdns, QByteArray::Base64UrlEncoding);

            //Got to interpret it differently based on the protocol version though
            ModernBuffer buffer(unbased);
            buffer.unpack("BIz", &protocolVersion, &props, &addr);
            switch(protocolVersion)
            {
            case 0:
                //qDebug() << "Protocol version 0x0000 read -> Plain DNS! You should enter it in the app plainly too, addr:" << addr << "props:" << props;
                return;

            case 1:
                buffer.unpack("zz", &providerPubKey, &providerName);
                //qDebug() << "Protocol version 0x0001 read -> DNSCrypt!";
                //qDebug() << "Provider name:" << providerName << "ProviderPubKey:" << providerPubKey << "props:" << props;

                if(providerPubKey.size() != crypto_box_PUBLICKEYBYTES)
                {
                    qDebug() << "PubKey length isn't right! Invalid stamp!";
                    return;
                }
                break;

            case 2:
                unpackHashes(buffer);
                buffer.unpack("zz", &hostname, &path);
                origHost = hostname;
                port2 = DNSInfo::extractPort(hostname);
                //qDebug() << "Protocol version 0x0002 read -> DNS over HTTPS!";
                //qDebug() << "Host:" << hostname << "Path:" << path;
                break;

            case 3:
                unpackHashes(buffer);
                buffer.unpack("z", &hostname);
                origHost = hostname;
                port2 = DNSInfo::extractPort(hostname);
                //qDebug() << "Protocol version 0x0003 read -> DNS over TLS!";
                //qDebug() << "Host:" << hostname;
                break;

            default:
                qDebug() << "Unknown and unsupported protocol version...";
                break;
            }

            props = qToBigEndian(props);
            //if(props & 1) qDebug() << "Provider supports DNSSEC";
            //if(props & 2) qDebug() << "Provider doesn't keep logs";
            //if(props & 4) qDebug() << "Provider doesn't intentionally block domains";

            origAddr = addr;
            port = DNSInfo::extractPort(addr);
            if(port == 443 && port2 != 0) port = port2;
            //qDebug() << "Provider using address:" << addr << "and port:" << port;
        }
    }

    QString toStamp()
    {
        QString txtStamp = "sdns://";
        ModernBuffer buffer;

        buffer.flags = 0;
        buffer.pack("BIz", &protocolVersion, &props, &addr);
        switch(protocolVersion)
        {
        case 0:
            break;

        case 1:
            buffer.pack("zz", &providerPubKey, &providerName);
            if(providerPubKey.size() != crypto_box_PUBLICKEYBYTES)
            {
                qDebug() << "PubKey length isn't right! Invalid stamp!";
                return "";
            }
            break;

        case 2:
            packHashes(buffer);
            buffer.pack("zz", &origHost, &path);
            break;

        case 3:
            packHashes(buffer);
            buffer.pack("z", &origHost);
            break;

        default:
            qDebug() << "Unknown and unsupported protocol version...";
            break;
        }

        txtStamp += buffer.buf.toBase64(QByteArray::Base64UrlEncoding).toStdString().c_str();
        return txtStamp;
    }

    void packHashes(ModernBuffer &buffer)
    {
        int hashCount = hashes.size(), hashLen, i = 0;
        for(QByteArray &hash : hashes)
        {
            hashLen = hash.size();
            i++;
            if(i != hashCount)
                hashLen |= 0x80;
            buffer.pack("Bx", &hashLen, &hash);
        }
    }
    void unpackHashes(ModernBuffer &buffer)
    {
        hashes.clear();
        quint8 hashLen;
        QByteArray hash;
        buffer.unpack("B", &hashLen);
        if(hashLen == 0) return;
        while(hashLen & 0x80)
        {
            hashLen &= ~0x80;
            buffer.unpack(QString("[%1]").arg(hashLen).toStdString().c_str(), &hash);
            hashes.append(hash);
            buffer.unpack("B", &hashLen);
        }
        buffer.unpack(QString("[%1]").arg(hashLen).toStdString().c_str(), &hash);
        hashes.append(hash);
    }

    quint8 protocolVersion;
    quint16 port;
    quint64 props;
    QString providerName, hostname, path, addr, origAddr, origHost;
    QByteArray providerPubKey;
    QVector<QByteArray> hashes;
};

class ProviderFromSource
{
public:
    QByteArray name, description, stamp;
    ProviderFromSource() { }
    ProviderFromSource(const QByteArray &name, const QByteArray &description, const QByteArray &stamp)
    {
        this->name = name;
        this->description = description;
        this->stamp = stamp;
    }
};

class ProviderSource : public QObject
{
    Q_OBJECT
public:
    QSslSocket tls;
    QByteArray data, hash, oldhash, downloadRequest;
    QString url, userAgent, sourcesDir, sourcesName, filePath;
    QDateTime lastUpdated;
    QVector<ProviderFromSource> providers;
    int offset;
    bool fileWasLoaded;

    ProviderSource()
    {
        init();
        connectUp();
    }
    ProviderSource(const QString &url, const QByteArray &hash = "", const QDateTime lastUpdated = QDateTime())
    {
        init();
        this->url = url;
        this->hash = hash;
        this->lastUpdated = lastUpdated;

        sourcesDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
        sourcesDir += QDir::separator();
        sourcesDir += "sources";
        QDir d{sourcesDir};
        if(d.mkpath(d.absolutePath()))
            qDebug() << "YourFriendlyDNS sources storage path:" << sourcesDir;

        int lastSlash = url.lastIndexOf("/");
        if(lastSlash != -1)
            filePath = sourcesDir + QDir::separator() + url.right(url.size() - (lastSlash + 1));

        connectUp();
    }
    ProviderSource(const ProviderSource &src) : QObject(nullptr)
    {
        copyFrom(src);
        connectUp();
    }
    ProviderSource operator=(const ProviderSource &src)
    {
        copyFrom(src);
        return *this;
    }
    void copyFrom(const ProviderSource &src)
    {
        this->data = src.data;
        this->url = src.url;
        this->hash = src.hash;
        this->lastUpdated = src.lastUpdated;
        this->sourcesName = src.sourcesName;
        this->filePath = src.filePath;
    }
    void init()
    {
        lastUpdated = QDateTime();
        offset = 0;
        fileWasLoaded = false;
        this->userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:60.0) Gecko/20100101 Firefox/60.0";
    }
    void connectUp()
    {
        connect(&tls, &QSslSocket::encrypted, this, &ProviderSource::requestDownloadOfSource);
        connect(&tls, &QSslSocket::readyRead, this, &ProviderSource::receiveDownloadOfSource);
    }

    void triggerDisplay()
    {
        if(data.size() == 0) load();
        emit displayProviders(providers);
    }

    void downloadAndUpdate()
    {
        download();
    }

    void downloadAndUpdateIfNeeded()
    {
        if(hash == "" || lastUpdated.daysTo(QDateTime::currentDateTime()) > 30)
            download();
        else
            load();
    }

    void load()
    {
        QFile f(filePath);
        if(f.open(QFile::ReadOnly))
        {
            qDebug() << "loaded from:" << filePath;
            data = f.readAll();
            if(data.size() == 0)
            {
                f.close();
                download();
                return;
            }
            interpretData(data);
            displayProviders(providers);

            f.close();
            fileWasLoaded = true;
        }
        else
            download();
    }

    void download()
    {
        quint16 port = 443;
        QString host, path, temp = url;
        QString get_request_header = R"(GET %1 HTTP/1.1
Host: %2
User-Agent: %3
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: identity
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0)";
        get_request_header += "\r\n\r\n";

        if(temp.startsWith("https://"))
            temp.remove(0, 8);
        else if(temp.startsWith("http://"))
        {
            temp.remove(0, 7);
            port = 80;
        }

        int slashPos = temp.indexOf("/");
        if(slashPos != -1)
        {
            host = temp.left(slashPos);
            path = temp.right(temp.size() - slashPos);

            downloadRequest.clear();
            downloadRequest.append(get_request_header.arg(path, host, userAgent));

            tls.connectToHostEncrypted(host, port, host);
        }
    }

private:
    QByteArray extractLine(int startingFrom)
    {
        int endL = data.indexOf("\n", startingFrom);
        if(endL != -1)
        {
            QByteArray line;
            line.resize(endL - startingFrom);
            memcpy(line.data(), &data.data()[startingFrom], endL - startingFrom);
            offset += (endL - startingFrom) + 1;
            return line;
        }
        return "";
    }

    QByteArray extractFromTo(int startingFrom, int to)
    {
        if(startingFrom < data.size() && to < data.size())
        {
            QByteArray extracted;
            extracted.resize(to - startingFrom);
            memcpy(extracted.data(), &data.data()[startingFrom], to - startingFrom);
            offset += (to - startingFrom);
            return extracted;
        }
        return "";
    }

    void interpretData(const QByteArray &data)
    {
        if(data.startsWith("# "))
        {
            offset = 0;
            providers.clear();
            sourcesName = extractLine(2);

            int entryFound = data.indexOf("## "), sdnsOffset;
            while(entryFound != -1)
            {
                entryFound += 3;
                QByteArray listedName, description, stamp;

                sdnsOffset = data.indexOf("sdns://", entryFound);
                if(sdnsOffset != -1)
                {
                    listedName = extractLine(entryFound);
                    description = extractFromTo(entryFound + offset, sdnsOffset);
                    stamp = extractLine(entryFound + offset);

                    //qDebug() << "Read Entry! listedName:" << listedName << "description:" << description << "stamp:" << stamp;

                    providers.append(ProviderFromSource(listedName, description, stamp));
                }

                entryFound = data.indexOf("## ", entryFound + offset);
                offset = 0;
            }

            oldhash = hash;
            hash = QCryptographicHash::hash(data, QCryptographicHash::Sha256);
        }
    }

    void saveData()
    {
        QFile f(filePath);
        if(f.open(QFile::WriteOnly))
        {
            f.write(data);
            f.close();
        }
    }

private slots:
    void requestDownloadOfSource()
    {
        data.clear();
        tls.write(downloadRequest);
    }

    void receiveDownloadOfSource()
    {
        QByteArray response = tls.readAll();
        if(data.size() == 0)
        {
            int contentLocated = response.lastIndexOf("\r\n\r\n");
            if(contentLocated != -1)
                response.remove(0, contentLocated + 4);
        }
        data += response;

        interpretData(data);
        if(hash != oldhash || !fileWasLoaded)
        {
            lastUpdated = QDateTime::currentDateTime();
            saveData();
            qDebug() << "Saved updated sources list!" << sourcesName << "New hash:" << hash << "old hash:" << oldhash;
        }
        emit displayProviders(providers);
    }

signals:
    void displayProviders(QVector<ProviderFromSource> &displayProviders);

};

class DoHDoTLSResponse : public QObject
{
    Q_OBJECT
public:
    explicit DoHDoTLSResponse(DNSInfo &dns, const QByteArray &dohRequest = QByteArray(), QObject *parent = nullptr);

    DNSInfo respondTo;
    QByteArray dohrequest;
    QSslSocket tls;

signals:
    void decryptedLookupDoneSendResponseNow(QByteArray response, DNSInfo &dns);

public slots:
    void verifyError(const QSslError error);
    void startEncryption();
    void writeEncryptedDoH();
    void getAndDecryptResponseDoH();
    void writeEncryptedDoTLS();
    void getAndDecryptResponseDoTLS();
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
    void sendDoHDoTLS(DNSInfo &dns, DNSCryptProtocol protocol);
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
