#include "dnscrypt.h"

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
    dnsCryptEnabled = true;
    gotValidCert = false;

    if(sodium_init() < 0)
    {
        qDebug() << "[libsodium not initialized] :(";
        dnsCryptAvailable = false;
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
    txt.append((quint8)0);

    txt.append((char*)&question, sizeof question);
    qDebug() << "Built TXT query (to get and validate server certificate):" << txt;
}

void DNSCrypt::getValidServerCertificate(DNSInfo &dns)
{
    QByteArray request;
    buildTXTRecord(request);

    udp.writeDatagram(request, currentServer, currentPort);
    CertificateResponse *cr = new CertificateResponse(dns, providerName);
    if(cr)
    {
        certCache.append(cr);
        connect(this, &DNSCrypt::certificateVerifiedDoEncryptedLookup, cr, &CertificateResponse::certificateVerifiedDoEncryptedLookup);
        connect(cr, &CertificateResponse::decryptedLookupDoneSendResponseNow, this, &DNSCrypt::decryptedLookupDoneSendResponseNow2);
    }
}

void DNSCrypt::makeEncryptedRequest(DNSInfo &dns)
{
    if(!gotValidCert || changedProviders)
        getValidServerCertificate(dns);
    else
    {
        quint64 now = QDateTime::currentDateTime().toMSecsSinceEpoch();
        QString nowStr = QString("%1").arg(now);
        if(nowStr.size() > 10) { nowStr.truncate(10); now = nowStr.toULongLong(); }

        if(now > currentCert.ts_end)
        {
            qDebug() << "Certificate is no longer valid, requesting a fresh one! For provider:" << providerName;
            changedProviders = gotValidCert = false;
            lastCertUsed = currentCert;
            getValidServerCertificate(dns);
            return;
        }

        qDebug() << "Alright now let's encrypt :)";
        emit certificateVerifiedDoEncryptedLookup(currentCert, currentServer, currentPort, dns);
    }
}

void DNSCrypt::setProvider(QString dnscryptStamp)
{
    if(dnscryptStamp == currentStamp) return;

    DNSCryptProvider newProvider(dnscryptStamp.toUtf8());

    if(newProvider.protocolVersion != 1)
    {
        qDebug() << "I don't support DoH / DNS Over HTTPS just yet...";
        return;
    }

    if(providerSet) changedProviders = true;

    providerName = newProvider.providerName;
    memcpy(providerKey, newProvider.providerPubKey, sizeof providerKey);
    if(newProvider.isIPv4) currentServer = QHostAddress(newProvider.ipv4Address);
    else currentServer = QHostAddress(newProvider.ipv6Address);
    currentPort = newProvider.port;

    providerSet = true;
    currentStamp = dnscryptStamp;
    qDebug() << "Provider set!";
}

void DNSCrypt::validateCertificates()
{
    QByteArray datagram;
    QHostAddress sender;
    quint16 senderPort;
    bool foundMagic = false;
    int magicOffset;
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
            qDebug() << "Verifying XChacha20 cert";
            continue;
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

        quint64 now = QDateTime::currentDateTime().toMSecsSinceEpoch();
        QString nowStr = QString("%1").arg(now);
        if(nowStr.size() > 10) { nowStr.truncate(10); now = nowStr.toULongLong(); }
        quint64 ts_begin = bincertFields.ts_begin;
        quint64 ts_end = bincertFields.ts_end;

        qDebug() << "now:" << now << "tsbegin:" << ts_begin << "tsend:" << ts_end;

        if(now < ts_begin)
        {
            qDebug() << "Certificate is not yet valid";
            continue;
        }
        else if(now > ts_end)
        {
            qDebug() << "Certificate is no longer valid";
            continue;
        }
        else if(bincertFields.serial < currentCert.serial)
        {
            qDebug() << "Certificates serial is old, old serial:" << bincertFields.serial << "Current serial:" << currentCert.serial;
            continue;
        }

        qDebug() << "Current serial:" << currentCert.serial << "This serial:" << bincertFields.serial;

        lastCertUsed = currentCert;
        currentCert = bincertFields;
        gotValidCert = true;

        qDebug() << "Valid cert!!! We have successfully validated the server's certificate, we're good to encrypt!";
        emit certificateVerifiedDoEncryptedLookup(bincertFields, currentServer, currentPort);
        emit deleteOldCertificatesForProvider(providerName, bincertFields);
        return;
    }
}

void DNSCrypt::decryptedLookupDoneSendResponseNow2(const QByteArray &response, DNSInfo &dns)
{
    emit decryptedLookupDoneSendResponseNow(response, dns);
}

void DNSCrypt::deleteOldCertificatesForProvider(QString provider, SignedBincertFields newestCert)
{
    std::vector<int> forDeletion;
    for(int i = 0; i < certCache.size(); i++)
    {
        if(certCache.at(i)->providerName == provider && newestCert.serial > certCache.at(i)->bincertFields.serial)
            forDeletion.push_back(i);
    }

    for(int &i : forDeletion)
    {
        CertificateResponse *cr = certCache.at(i);
        certCache.remove(i);
        if(cr)
            delete cr;
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

    connect(&tcp, SIGNAL(connected()), this, SLOT(writeEncryptedRequestTCP()));
    connect(&tcp, SIGNAL(readyRead()), this, SLOT(getAndDecryptResponseTCP()));
    connect(&udp, SIGNAL(readyRead()), this, SLOT(getAndDecryptResponse()));
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
    QByteArray packet = tcp.readAll();

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

    qDebug() << "Encrypted message size:" << packet.size() << "data:" << packet;

    if(memcmp(&responseHeader.ServerMagic, DNSCRYPT_MAGIC_RESPONSE, sizeof responseHeader.ServerMagic) == 0)
    {
        qDebug() << "We still have the magic over TCP! :)";

        if(memcmp(&responseHeader.ClientNonce, nonce, sizeof(crypto_box_HALF_NONCEBYTES)) != 0)
        {
            qDebug() << "Unexpected nonce...";
            return endResponse();
        }

        quint32 decryptedLen = prependedPacketLen - crypto_box_MACBYTES;
        quint8 decrypted[decryptedLen];
        memset(decrypted, 0, sizeof decrypted);
        memcpy(&nonce[crypto_box_HALF_NONCEBYTES], &responseHeader.ServerNonce, crypto_box_HALF_NONCEBYTES);

        QByteArray response;
        if(crypto_box_open_easy(decrypted, (quint8*)packet.data(), packet.size(), nonce, bincertFields.server_publickey, sk) != 0)
        {
            response.append((char*)&decrypted, decryptedLen);
            qDebug() << "Decryption failed... :(" << response;
            return endResponse();
        }

        response.append((char*)&decrypted, decryptedLen);
        removePadding(response);
        emit decryptedLookupDoneSendResponseNow(response, respondTo);

        qDebug() << "Returned decrypted response!:" << response;
        return endResponse();
    }
}

void EncryptedResponse::getAndDecryptResponse()
{
    if(responseHandled) return;

    QByteArray datagram;
    QHostAddress sender;
    quint16 senderPort;

    while(udp.hasPendingDatagrams())
    {
        dnsCryptResponseHeader responseHeader;

        datagram.resize(udp.pendingDatagramSize());
        udp.readDatagram(datagram.data(), datagram.size(), &sender, &senderPort);

        qDebug() << "Received encrypted UDP datagram:" << datagram << "with size:" << datagram.size();

        if(datagram.size() >= DNS_HEADER_SIZE)
        {
            DNS_HEADER *dnsh = (DNS_HEADER*)datagram.data();
            if(dnsh->tc == 1)
            {
                qDebug() << "TCFlag set, it wants us to use TCP! Switching now for provider:" << providerName;
                emit switchToTCP(respondTo, encRequest, bincertFields, providerName, nonce, sk);
                return endResponse();
            }
        }
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

            quint32 decryptedLen = datagram.size() - crypto_box_MACBYTES;
            quint8 decrypted[decryptedLen];
            memset(decrypted, 0, sizeof decrypted);
            memcpy(&nonce[crypto_box_HALF_NONCEBYTES], &responseHeader.ServerNonce, crypto_box_HALF_NONCEBYTES);

            QByteArray response;
            if(crypto_box_open_easy((quint8*)&decrypted, (quint8*)datagram.data(), datagram.size(), nonce, bincertFields.server_publickey, sk) != 0)
            {
                response.append((char*)&decrypted, decryptedLen);
                qDebug() << "Not decrypted..." << response;
                return endResponse();
            }

            response.append((char*)&decrypted, decryptedLen);
            removePadding(response);
            emit decryptedLookupDoneSendResponseNow(response, respondTo);

            qDebug() << "Returned decrypted response!:" << response;
            return endResponse();
        }
    }
}

CertificateResponse::CertificateResponse(DNSInfo &dns, QString providername, QObject *parent)
{
    Q_UNUSED(parent);
    respondTo = dns;
    respondTo.req = dns.req;
    providerName = providername;
    usingTCP = false;
    newKeyPerRequest = false;
    crypto_box_keypair(pk, sk);
    qDebug() << "Aquired new certificate for provider:" << providername;
}

void CertificateResponse::addPadding(QByteArray &msg)
{
    uint32_t padding = DNSCRYPT_MAX_PADDING;

    while(((msg.size() + padding) % 64) != 0)
    {
        padding--;
    }

    qDebug() << padding << "bytes of padding chosen! new msg size:" << msg.size() + padding;

    for(uint32_t i = 0; i < padding; i++)
    {
        if(i == 0)
            msg.append((quint8)0x80);
        else
            msg.append((quint8)0);
    }
}

void CertificateResponse::switchToTCP(DNSInfo &dns, QByteArray encryptedRequest, SignedBincertFields signedBincertFields, QString providername, quint8 *nonce, quint8 *sk)
{
    usingTCP = true;
    quint16 prependedPacketLen = encryptedRequest.size();
    prependedPacketLen = qToBigEndian(prependedPacketLen);
    encryptedRequest.prepend((const char*)&prependedPacketLen, 2);

    EncryptedResponse *er2 = new EncryptedResponse(dns, encryptedRequest, signedBincertFields, providername, nonce, sk);
    if(er2)
    {
        connect(er2, &EncryptedResponse::decryptedLookupDoneSendResponseNow, this, &CertificateResponse::decryptedLookupDoneSendResponseNow);
        er2->tcp.connectToHost(currentServer, currentPort);
    }
}

void CertificateResponse::certificateVerifiedDoEncryptedLookup(SignedBincertFields bincertFields, QHostAddress serverAddress, quint16 serverPort, DNSInfo dns)
{
    dnsCryptQueryHeader queryHeader;
    QByteArray unencryptedRequest, encryptedRequest;
    quint8 nonce[crypto_box_NONCEBYTES] = {0};

    currentServer = serverAddress;
    currentPort = serverPort;

    if(newKeyPerRequest)
        crypto_box_keypair(pk, sk);

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
    quint8 rawEncryptedRequest[encryptedSize];

    if(crypto_box_easy(rawEncryptedRequest, (quint8*)unencryptedRequest.data(), unencryptedRequest.size(), nonce, bincertFields.server_publickey, sk) != 0)
    {
        qDebug() << "Encryption failed... :(";
        return;
    }

    encryptedRequest.append((char*)&queryHeader, sizeof queryHeader);
    encryptedRequest.append((char*)rawEncryptedRequest, encryptedSize);

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
        connect(er, &EncryptedResponse::switchToTCP, this, &CertificateResponse::switchToTCP, Qt::DirectConnection);
        connect(er, &EncryptedResponse::decryptedLookupDoneSendResponseNow, this, &CertificateResponse::decryptedLookupDoneSendResponseNow);

        if(usingTCP)
        {
            er->tcp.connectToHost(serverAddress, serverPort);
        }
        else
        {
            er->udp.writeDatagram(encryptedRequest, serverAddress, serverPort);
        }
    }
}
