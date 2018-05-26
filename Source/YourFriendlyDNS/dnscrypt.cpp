#include "dnscrypt.h"

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

DNSCrypt::DNSCrypt(QObject *parent)
{
    Q_UNUSED(parent);

    //Default is opendns dnscrypt
    providerName = "2.dnscrypt-cert.opendns.com";
    //opendns dnscrypt pub key: B735:1140:206F:225D:3E2B:D822:D7FD:691E:A1C3:3CC8:D666:8D0C:BE04:BFAB:CA43:FB79
    quint8 defaultProviderPubKey[crypto_box_PUBLICKEYBYTES] = {0xB7, 0x35, 0x11, 0x40, 0x20, 0x6F, 0x22, 0x5D, 0x3E, 0x2B, 0xD8, 0x22, 0xD7, 0xFD, 0x69, 0x1E, 0xA1, 0xC3, 0x3C, 0xC8, 0xD6, 0x66, 0x8D, 0x0C, 0xBE, 0x04, 0xBF, 0xAB, 0xCA, 0x43, 0xFB, 0x79};
    memcpy(&providerKey, &defaultProviderPubKey, sizeof defaultProviderPubKey);
    quint8 serverMagic[DNSCRYPT_MAGIC_QUERY_LEN] = {0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38};
    memcpy(&resolverMagic, &serverMagic, sizeof serverMagic);
    memset(&currentCert, 0, sizeof currentCert);
    currentServer = QHostAddress("208.67.220.220");
    currentPort = 443;
    protocolVersion = 1;
    dnsCryptEnabled = true;
    newKeyPerRequest = pendingValidation = false;
    userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:60.0) Gecko/20100101 Firefox/60.0";

    if(sodium_init() < 0)
    {
        qDebug() << "[libsodium not initialized] :(";
        dnsCryptAvailable = dnsCryptEnabled = false;
    }
    else
    {
        qDebug() << "[libsodium initialized successfully] :) Yes! We can dnscrypt now!";
        dnsCryptAvailable = true;
        connect(&udp, &QUdpSocket::readyRead, this, &DNSCrypt::validateCertificates);
    }
}

void DNSCrypt::buildTXTRecord(QByteArray &txt)
{
    DNS_HEADER header;
    QUESTION question;
    memset(&header, 0, sizeof header);

    header.id = randombytes_random();
    header.rd = 1;
    header.q_count = qToBigEndian((quint16)1);

    question.qtype = qToBigEndian((quint16)DNS_TYPE_TXT);
    question.qclass = qToBigEndian((quint16)1);

    txt.append((char*)&header, sizeof header);

    QStringList parts = providerName.split(".");
    for(QString &p : parts)
    {
        quint8 s = p.size();
        txt.append(s);
        txt.append(p);
    }
    txt.append((char)0);

    txt.append((char*)&question, sizeof question);
    qDebug() << "Built TXT query (to get and validate server certificate):" << txt;
}

void DNSCrypt::getValidServerCertificate(DNSInfo &dns)
{
    pendingValidation = true;

    QByteArray txt;
    buildTXTRecord(txt);

    udp.writeDatagram(txt, currentServer, currentPort);
    CertificateHolder *cr = new CertificateHolder(dns, providerName, currentServer, currentPort);
    if(cr)
    {
        certCache.append(cr);
        connect(this, &DNSCrypt::certificateVerifiedDoEncryptedLookup, cr, &CertificateHolder::certificateVerifiedDoEncryptedLookup);
        connect(cr, &CertificateHolder::decryptedLookupDoneSendResponseNow, this, &DNSCrypt::decryptedLookupDoneSendResponseNow);
    }
}

CertificateHolder *DNSCrypt::getCachedCert(QHostAddress server, QString provider)
{
    for(CertificateHolder *c : certCache)
    {
        if(c->certServer == server && c->providerName == provider)
        {
            return c;
        }
    }
    return nullptr;
}

DoHDoTLSResponse::DoHDoTLSResponse(DNSInfo &dns, const QByteArray &dohRequest, QObject *parent)
{
    Q_UNUSED(parent);
    respondTo = dns;

    connect(&tls, SIGNAL(disconnected()), this, SLOT(deleteLater()));
    connect(&tls, &QSslSocket::peerVerifyError, this, &DoHDoTLSResponse::verifyError);

    if(dohRequest.size() > 0)
    {
        dohrequest = dohRequest;
        connect(&tls, SIGNAL(encrypted()), this, SLOT(writeEncryptedDoH()));
        connect(&tls, SIGNAL(readyRead()), this, SLOT(getAndDecryptResponseDoH()));
    }
    else
    {
        connect(&tls, SIGNAL(encrypted()), this, SLOT(writeEncryptedDoTLS()));
        connect(&tls, SIGNAL(readyRead()), this, SLOT(getAndDecryptResponseDoTLS()));
    }
}

void DoHDoTLSResponse::verifyError(const QSslError error)
{
    qDebug() << "TLS Error:" << error.errorString();
}

void DoHDoTLSResponse::startEncryption()
{
    qDebug() << "Starting encryption! peerAddress:" << tls.peerAddress() << "port:" << tls.peerPort();
    tls.startClientEncryption();
}

void DoHDoTLSResponse::writeEncryptedDoH()
{
    tls.write(dohrequest);
    qDebug() << "Sent DoH request:" << dohrequest;
}

void DoHDoTLSResponse::getAndDecryptResponseDoH()
{
    QByteArray decryptedResponse = tls.readAll(); //Well, TLS decrypts it for us...
    qDebug() << "Received DoH response:" << decryptedResponse;
    if(decryptedResponse.size() > 0 && decryptedResponse.contains("200 OK"))
    {
        int contentPos = decryptedResponse.lastIndexOf("\r\n\r\n");
        if(contentPos != -1)
        {
            decryptedResponse.remove(0, contentPos + 4);
            qDebug() << "Just the dns message:" << decryptedResponse;
            emit decryptedLookupDoneSendResponseNow(decryptedResponse, respondTo);
        }
    }
}

void DoHDoTLSResponse::writeEncryptedDoTLS()
{
    quint16 prependedLen = respondTo.req.size();
    prependedLen = qToBigEndian(prependedLen);
    respondTo.req.prepend((const char*)&prependedLen, 2);

    tls.write(respondTo.req);
    qDebug() << "Sent DoTLS request:" << respondTo.req;
}

void DoHDoTLSResponse::getAndDecryptResponseDoTLS()
{
    QByteArray decryptedResponse = tls.readAll();
    qDebug() << "Received DoTLS response:" << decryptedResponse;
    if(decryptedResponse.size() > 2)
    {
        decryptedResponse.remove(0, 2);
        emit decryptedLookupDoneSendResponseNow(decryptedResponse, respondTo);
    }
}

void DNSCrypt::sendDoHDoTLS(DNSInfo &dns, DNSCryptProtocol protocol)
{
    QByteArray dohRequest;
    if(protocol == DNSCryptProtocol::DNSoverHTTPS)
    {
        QString post_request_header=R"(POST %1 HTTP/1.1
Host: %2
User-Agent: %3
Accept: application/dns-udpwireformat
Content-Type: application/dns-udpwireformat
Content-Length: %4)";
        post_request_header += "\r\n\r\n";

        dohRequest.append(post_request_header.arg(path).arg(hostname).arg(userAgent).arg(dns.req.size()));
        dohRequest.append(dns.req);
    }

    DoHDoTLSResponse *d = new DoHDoTLSResponse(dns, dohRequest);
    if(d)
    {
        connect(d, &DoHDoTLSResponse::decryptedLookupDoneSendResponseNow, this, &DNSCrypt::decryptedLookupDoneSendResponseNow);
        d->tls.setPeerVerifyName(hostname);
        if(currentServer.isNull())
            d->tls.connectToHostEncrypted(hostname, currentPort);
        else
        {
            connect(&d->tls, SIGNAL(connected()), d, SLOT(startEncryption()));
            d->tls.connectToHost(currentServer, currentPort);
        }
    }
}

void DNSCrypt::makeEncryptedRequest(DNSInfo &dns)
{
    if(protocolVersion == 1)
    {
        CertificateHolder *c = getCachedCert(currentServer, providerName);
        if(c != nullptr && !pendingValidation)
        {
            currentCert = c->bincertFields;
            if(getTimeNow() > currentCert.ts_end)
            {
                qDebug() << "Certificate is no longer valid, requesting a fresh one! For provider:" << providerName;
                getValidServerCertificate(dns);
                return;
            }

            qDebug() << "Alright now let's encrypt :) current server:" << currentServer << "current provider:" << providerName;
            emit certificateVerifiedDoEncryptedLookup(currentCert, currentServer, currentPort, newKeyPerRequest, dns);
        }
        else if(!pendingValidation)
            getValidServerCertificate(dns);
    }
    else if(protocolVersion == 2)
    {
        sendDoHDoTLS(dns, DNSCryptProtocol::DNSoverHTTPS);
    }
    else if(protocolVersion == 3)
    {
        sendDoHDoTLS(dns, DNSCryptProtocol::DNSoverTLS);
    }
}

void DNSCrypt::setProvider(QString dnscryptStamp)
{
    if(dnscryptStamp == currentStamp) return;

    DNSCryptProvider newProvider(dnscryptStamp.toUtf8());
    protocolVersion = newProvider.protocolVersion;
    if(protocolVersion == 0) return;

    hostname = newProvider.hostname;
    path = newProvider.path;
    currentPort = newProvider.port;

    //Because of stamp specification note, I resolve the ip to use from hostname if addr is empty or just a port (I take the port and set it empty in that case):
    //"addr is the IP address of the server. It can be an empty string, or just a port number. In that case, the host name will be resolved to an IP address using another resolver."
    if(newProvider.addr.size() == 0)
    {
        //Note: connectToHostEncrypted with hostname is used instead of connectToHost with ip when currentServer is null, which results in resolving it automatically,
        //and using this server itself if system dns is set to use it.
        currentServer.clear();
    }
    else
        currentServer = QHostAddress(newProvider.addr);

    if(protocolVersion == 1)
    {
        providerName = newProvider.providerName;
        if(newProvider.providerPubKey.size() == crypto_box_PUBLICKEYBYTES)
            memcpy(providerKey, newProvider.providerPubKey.data(), crypto_box_PUBLICKEYBYTES);

        emit displayLastUsedProvider(newProvider.props, providerName, currentServer, currentPort);
    }
    else if(protocolVersion == 2 || protocolVersion == 3)
    {
        emit displayLastUsedProvider(newProvider.props, hostname, currentServer, currentPort);
    }

    currentStamp = dnscryptStamp;
    qDebug() << "Provider set!";
}

quint64 DNSCrypt::getTimeNow()
{
    quint64 now = QDateTime::currentDateTime().toMSecsSinceEpoch();
    QString nowStr = QString("%1").arg(now);
    if(nowStr.size() > 10)
        nowStr.truncate(10);
    return nowStr.toULongLong();
}

void DNSCrypt::validateCertificates()
{
    QByteArray datagram;
    QHostAddress sender;
    quint16 senderPort;
    bool foundMagic = false;
    int magicOffset = 0;
    SignedBincert bincert;
    SignedBincertFields bincertFields;

    while(udp.hasPendingDatagrams())
    {
        datagram.resize(udp.pendingDatagramSize());
        udp.readDatagram(datagram.data(), datagram.size(), &sender, &senderPort);

        qDebug() << "TXT record response with certificate to validate:" << datagram;

        for(int i = 0; i < (datagram.size() - 5); i++)
        {
            if(memcmp(&datagram.data()[i], CERT_MAGIC_CERT, 5) == 0)
            {
                foundMagic = true;
                magicOffset = i;
                break;
            }
        }

        if(foundMagic)
        {
            datagram.remove(0, magicOffset);
            qDebug() << "We have the magic!";
        }
        else
        {
            qDebug() << "Cert magic not found...";
            continue;
        }

        memcpy(&bincert, datagram.data(), sizeof bincert);
        bincert.version_major = qFromBigEndian(bincert.version_major);
        bincert.version_minor = qFromBigEndian(bincert.version_minor);

        // Version indicates which crypto construction to use
        // For X25519-XSalsa20Poly1305, <es-version> must be 0x00 0x01.
        // For X25519-XChacha20Poly1305, <es-version> must be 0x00 0x02.
        if(bincert.version_major == 1)
        {
            qDebug() << "Verifying XSalsa20 cert...";
            if(crypto_sign_ed25519_verify_detached(bincert.signature, bincert.signed_data, sizeof bincert.signed_data, providerKey) != 0)
            {
                /* Incorrect signature! */
                qDebug() << "Incorrect signature...";
                continue;
            }
        }
        else if(bincert.version_major == 2)
        {
            qDebug() << "Verifying XChacha20 cert"; //Idk? What do I call differently?
            if(crypto_sign_ed25519_verify_detached(bincert.signature, bincert.signed_data, sizeof bincert.signed_data, providerKey) != 0)
            {
                /* Incorrect signature! */
                qDebug() << "Incorrect signature...";
                continue;
            }
        }
        else
        {
            qDebug() << "Invalid version, either XSalsa or XChacha there isn't another one supported! lol";
            continue;
        }

        memcpy(&bincertFields, bincert.signed_data, sizeof bincert.signed_data);
        bincertFields.ts_begin = qFromBigEndian(bincertFields.ts_begin);
        bincertFields.ts_end = qFromBigEndian(bincertFields.ts_end);
        bincertFields.serial = qFromBigEndian(bincertFields.serial);

        quint64 now = getTimeNow();
        qDebug() << "Current serial:" << currentCert.serial << "This serial:" << bincertFields.serial;

        if(now < bincertFields.ts_begin)
        {
            qDebug() << "Certificate is not yet valid";
            continue;
        }
        else if(now > bincertFields.ts_end)
        {
            qDebug() << "Certificate is no longer valid";
            continue;
        }
        else if(bincertFields.serial < currentCert.serial)
        {
            qDebug() << "Certificates serial is old, old serial:" << bincertFields.serial << "Current serial:" << currentCert.serial;
            continue;
        }
        currentCert = bincertFields;

        qDebug() << "Valid cert!!! We have successfully validated the server's certificate, we're good to encrypt!";
        emit certificateVerifiedDoEncryptedLookup(bincertFields, currentServer, currentPort, newKeyPerRequest);
        emit deleteOldCertificatesForProvider(providerName, currentServer, bincertFields);
        pendingValidation = false;
        return;
    }
}

void DNSCrypt::deleteOldCertificatesForProvider(QString provider, QHostAddress server, SignedBincertFields newestCert)
{
    bool isDuplicate = false;
    for(int i = 0; i < certCache.size(); i++)
    {
        if((certCache.at(i)->providerName == provider && certCache.at(i)->certServer == server))
        {
            if(memcmp(&certCache.at(i)->bincertFields, &newestCert, sizeof(SignedBincertFields)) == 0)
            {
                if(!isDuplicate)
                    isDuplicate = true;
                else
                {
                    qDebug() << "Deleting duplicate certificate, for provider:" << provider << "server:" << server << "cert serial:" << newestCert.serial;
                    CertificateHolder *cr = certCache.at(i);
                    certCache.remove(i);
                    delete cr;
                    i--;
                    continue;
                }
            }

            if(newestCert.serial > certCache.at(i)->bincertFields.serial)
            {
                qDebug() << "Deleting certificate, for provider:" << provider << "newer serial:" << newestCert.serial << "older:" << certCache.at(i)->bincertFields.serial;
                CertificateHolder *cr = certCache.at(i);
                certCache.remove(i);
                delete cr;
                i--;
            }
        }
    }
}

EncryptedResponse::EncryptedResponse(DNSInfo &dns, QByteArray encryptedRequest, SignedBincertFields signedBincertFields, QString providername, quint8 *nonce, quint8 *sk, QObject *parent)
{
    Q_UNUSED(parent);

    respondTo = dns;
    encRequest = encryptedRequest;
    providerName = providername;
    bincertFields = signedBincertFields;
    responseHandled = false;
    memcpy(this->sk, sk, crypto_box_SECRETKEYBYTES);
    memcpy(this->nonce, nonce, crypto_box_NONCEBYTES);

    connect(&tcp, SIGNAL(disconnected()), this, SLOT(deleteLater()));
    connect(&tcp, SIGNAL(connected()), this, SLOT(writeEncryptedRequestTCP()));
    connect(&tcp, SIGNAL(readyRead()), this, SLOT(getAndDecryptResponseTCP()));
    connect(&udp, SIGNAL(readyRead()), this, SLOT(getAndDecryptResponse()));
    connect(&udp, QOverload<QAbstractSocket::SocketError>::of(&QAbstractSocket::error), this, &EncryptedResponse::socketError);
}

void EncryptedResponse::socketError(QAbstractSocket::SocketError error)
{
    qDebug() << "Socket Error:" << error;
    endResponse();
}

void EncryptedResponse::endResponse()
{
    responseHandled = true;
    this->deleteLater();
}

void EncryptedResponse::removePadding(QByteArray &msg)
{
    if(msg.endsWith((char)0x00))
    {
        for(int i = msg.size(); i > 0; i--)
        {
            if(msg.data()[i] == (char)0x80) // 0x80 == padding start
            {
                msg.truncate(i);
                return;
            }
        }
    }
}

void EncryptedResponse::writeEncryptedRequestTCP()
{
    tcp.write(encRequest);
    qDebug() << "TCP Connected... wrote:" << encRequest;
}

void EncryptedResponse::getAndDecryptResponseTCP()
{
    if(responseHandled) return;

    dnsCryptResponseHeader responseHeader;
    QByteArray packet = tcp.readAll(), decrypted;

    qDebug() << "Received encrypted TCP packet:" << packet << "with size:" << packet.size();
    if((quint32)packet.size() < sizeof responseHeader)
    {
        qDebug() << "Packet too small...";
        return endResponse();
    }

    quint16 prependedPacketLen = qFromBigEndian(*(quint16*)packet.data());
    packet.remove(0, 2);

    memcpy(&responseHeader, packet.data(), sizeof responseHeader);
    packet.remove(0, sizeof responseHeader);
    prependedPacketLen -= sizeof responseHeader;

    if(memcmp(&responseHeader.ServerMagic, DNSCRYPT_MAGIC_RESPONSE, sizeof responseHeader.ServerMagic) == 0)
    {
        qDebug() << "We still have the magic over TCP! :)";

        if(memcmp(&responseHeader.ClientNonce, nonce, sizeof(crypto_box_HALF_NONCEBYTES)) != 0)
        {
            qDebug() << "Unexpected nonce...";
            return endResponse();
        }

        quint32 decryptedLen = prependedPacketLen - crypto_box_MACBYTES;
        decrypted.resize(decryptedLen);
        memcpy(&nonce[crypto_box_HALF_NONCEBYTES], &responseHeader.ServerNonce, crypto_box_HALF_NONCEBYTES);

        QByteArray response;
        if(crypto_box_open_easy((quint8*)decrypted.data(), (quint8*)packet.data(), packet.size(), nonce, bincertFields.server_publickey, sk) != 0)
        {
            qDebug() << "Decryption failed..." << response;
            return endResponse();
        }

        response.append(decrypted);
        removePadding(response);
        emit decryptedLookupDoneSendResponseNow(response, respondTo);
        return endResponse();
    }
}

void EncryptedResponse::getAndDecryptResponse()
{
    if(responseHandled) return;

    QByteArray datagram, decrypted;
    QHostAddress sender;
    quint16 senderPort;

    while(udp.hasPendingDatagrams())
    {
        dnsCryptResponseHeader responseHeader;

        datagram.resize(udp.pendingDatagramSize());
        udp.readDatagram(datagram.data(), datagram.size(), &sender, &senderPort);

        qDebug() << "Received encrypted UDP datagram:" << datagram << "with size:" << datagram.size();


        if((quint32)datagram.size() < sizeof responseHeader)
        {
            qDebug() << "Datagram too small...";
            return endResponse();
        }

        memcpy(&responseHeader, datagram.data(), sizeof responseHeader);
        datagram.remove(0, sizeof responseHeader);

        if(memcmp(&responseHeader.ServerMagic, DNSCRYPT_MAGIC_RESPONSE, sizeof responseHeader.ServerMagic) == 0)
        {
            qDebug() << "We still have the magic! :)";

            if(memcmp(&responseHeader.ClientNonce, nonce, sizeof(crypto_box_HALF_NONCEBYTES)) != 0)
            {
                qDebug() << "Unexpected nonce...";
                return endResponse();
            }

            quint32 decryptedLen = datagram.size() - crypto_box_MACBYTES;
            decrypted.resize(decryptedLen);
            memcpy(&nonce[crypto_box_HALF_NONCEBYTES], &responseHeader.ServerNonce, crypto_box_HALF_NONCEBYTES);

            QByteArray response;
            if(crypto_box_open_easy((quint8*)decrypted.data(), (quint8*)datagram.data(), datagram.size(), nonce, bincertFields.server_publickey, sk) != 0)
            {
                qDebug() << "Not decrypted..." << response;
                return endResponse();
            }

            if(decrypted.size() >= DNS_HEADER_SIZE)
            {
                if(((DNS_HEADER*)decrypted.data())->tc == 1)
                {
                    qDebug() << "TCFlag set / truncated message, using tcp for this request:" << encRequest;
                    emit resendUsingTCP(respondTo, encRequest, bincertFields, providerName, nonce, sk);
                    return endResponse();
                }
            }

            response.append(decrypted);
            removePadding(response);
            emit decryptedLookupDoneSendResponseNow(response, respondTo);
            return endResponse();
        }
    }
    return endResponse();
}

CertificateHolder::CertificateHolder(DNSInfo &dns, QString providername, QHostAddress server, quint16 port, QObject *parent)
{
    Q_UNUSED(parent);
    respondTo = dns;
    providerName = providername;
    usingTCP = false;
    certServer = server;
    serverPort = port;
    nextRotateKeyTime = QDateTime::currentDateTime().currentMSecsSinceEpoch() + (randombytes_random() % 86400000);
    crypto_box_keypair(pk, sk);
}

void CertificateHolder::addPadding(QByteArray &msg)
{
    quint32 padding = DNSCRYPT_MAX_PADDING;

    while(((msg.size() + padding) % DNSCRYPT_BLOCK_SIZE) != 0)
    {
        padding--;
    }

    qDebug() << padding << "bytes of padding chosen! new msg size:" << msg.size() + padding;

    msg.append((char)0x80);
    for(quint32 i = 1; i < padding; i++)
    {
        msg.append((char)0);
    }
}

void CertificateHolder::resendUsingTCP(DNSInfo &dns, QByteArray encryptedRequest, SignedBincertFields signedBincertFields, QString providername, quint8 *nonce, quint8 *sk)
{
    quint16 prependedPacketLen = encryptedRequest.size();
    prependedPacketLen = qToBigEndian(prependedPacketLen);
    encryptedRequest.prepend((const char*)&prependedPacketLen, 2);

    EncryptedResponse *er2 = new EncryptedResponse(dns, encryptedRequest, signedBincertFields, providername, nonce, sk);
    if(er2)
    {
        connect(er2, &EncryptedResponse::decryptedLookupDoneSendResponseNow, this, &CertificateHolder::decryptedLookupDoneSendResponseNow);
        er2->tcp.connectToHost(certServer, serverPort);
    }
}

void CertificateHolder::certificateVerifiedDoEncryptedLookup(SignedBincertFields bincertFields, QHostAddress serverAddress, quint16 serverPort, bool newKey, DNSInfo dns)
{
    dnsCryptQueryHeader queryHeader;
    QByteArray unencryptedRequest, encryptedRequest, rawEncryptedRequest;
    quint8 nonce[crypto_box_NONCEBYTES] = {0};

    if(serverAddress != certServer)
    {
        qDebug() << "Not the right server for certificate:" << serverAddress << "Cert server:" << certServer;
        return;
    }

    if(newKey)
        crypto_box_keypair(pk, sk);
    else
    {
        quint64 currentTime = QDateTime::currentDateTime().currentMSecsSinceEpoch();
        if(currentTime > nextRotateKeyTime)
        {
            crypto_box_keypair(pk, sk);
            nextRotateKeyTime = QDateTime::currentDateTime().currentMSecsSinceEpoch() + (randombytes_random() % 86400000);
            qDebug() << "New key created! Next key rotate time:" << nextRotateKeyTime;
        }
    }

    this->bincertFields = bincertFields;
    memset(&queryHeader, 0, sizeof queryHeader);
    memcpy(&queryHeader.ClientMagic, bincertFields.magic_query, sizeof bincertFields.magic_query);
    memcpy(&queryHeader.ClientPublicKey, pk, crypto_box_PUBLICKEYBYTES);
    randombytes_buf(&queryHeader.ClientNonce, crypto_box_HALF_NONCEBYTES);
    memcpy(nonce, &queryHeader.ClientNonce, crypto_box_HALF_NONCEBYTES);

    if(dns.req.size() == 0 && respondTo.req.size() > 0) //For first request using this certificate only
        dns.req = respondTo.req;

    unencryptedRequest.append(dns.req);
    qDebug() << "Request before padding:" << unencryptedRequest << "length:" << unencryptedRequest.size();

    addPadding(unencryptedRequest);
    qDebug() << "Request before encryption:" << unencryptedRequest << "length:" << unencryptedRequest.size();

    quint32 encryptedSize = unencryptedRequest.size() + crypto_box_MACBYTES;
    rawEncryptedRequest.resize(encryptedSize);

    if(crypto_box_easy((quint8*)rawEncryptedRequest.data(), (quint8*)unencryptedRequest.data(), unencryptedRequest.size(), nonce, bincertFields.server_publickey, sk) != 0)
    {
        qDebug() << "Encryption failed... :(";
        return;
    }

    encryptedRequest.append((char*)&queryHeader, sizeof queryHeader);
    encryptedRequest.append(rawEncryptedRequest);

    if(usingTCP)
    {
        quint16 prependedPacketLen = encryptedRequest.size();
        prependedPacketLen = qToBigEndian(prependedPacketLen);
        encryptedRequest.prepend((const char*)&prependedPacketLen, 2);
    }

    qDebug() << "Request after encryption:" << encryptedRequest << "size:" << encryptedRequest.size() << "encryptedSize:" << encryptedSize;
    qDebug() << "Sending to server:" << serverAddress << serverPort;

    EncryptedResponse *er = new EncryptedResponse(dns, encryptedRequest, bincertFields, providerName, nonce, sk);
    if(er)
    {
        connect(er, &EncryptedResponse::resendUsingTCP, this, &CertificateHolder::resendUsingTCP);
        connect(er, &EncryptedResponse::decryptedLookupDoneSendResponseNow, this, &CertificateHolder::decryptedLookupDoneSendResponseNow);

        if(usingTCP)
            er->tcp.connectToHost(serverAddress, serverPort);
        else
            er->udp.writeDatagram(encryptedRequest, serverAddress, serverPort);
    }
}
