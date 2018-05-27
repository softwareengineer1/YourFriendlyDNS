#include "smalldnsserver.h"

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

SmallDNSServer::SmallDNSServer(QObject *parent)
{
    Q_UNUSED(parent);
    ipToRespondWith = QHostAddress("127.0.0.1").toIPv4Address();
    cachedMinutesValid = 7;
    dnsTTL = 4200;
    inTimeout = 0;
    numSentRequests = numReceivedResponses = 0;
    dnscryptEnabled = true; //Encryption now enabled by default (and there's no fallback to plaintext dns either for security, you have to manually disable it to use regular dns again)
    dedicatedDNSCrypter = "sdns://AQAAAAAAAAAADjIwOC42Ny4yMjAuMjIwILc1EUAgbyJdPivYItf9aR6hwzzI1maNDL4Ev6vKQ_t5GzIuZG5zY3J5cHQtY2VydC5vcGVuZG5zLmNvbQ";

    whitelistmode = initialMode = blockmode_returnlocalhost = true;
    sendrecvFlag = false;
    //default is whitelist mode, with just these three entries to get you started!
    whitelist.push_back(ListEntry("*startpage.com"));
    whitelist.push_back(ListEntry("*ixquick-proxy.com"));
    whitelist.push_back(ListEntry("*gbatemp.net"));
    whitelist.push_back(ListEntry("*github.com"));

    //Just in case someone switches to blacklist right away and disables initial mode without setting it up
    //This initial default setup should at least help avert disaster, and this demonstrates that it supports wild cards!
    //*.srv.nintendo.net
    //*.d4c.nintendo.net
    //*.eshop.nintendo.net
    //*.cdn.nintendo.net
    blacklist.push_back(ListEntry("*srv.nintendo.net"));
    blacklist.push_back(ListEntry("*d4c.nintendo.net"));
    blacklist.push_back(ListEntry("*eshop.nintendo.net"));
    blacklist.push_back(ListEntry("*cdn.nintendo.net"));
    //Known captive portals (to keep them captive)
    blacklist.push_back(ListEntry("ctest.cdn.nintendo.net"));
    blacklist.push_back(ListEntry("conntest.nintendowifi.net"));
    blacklist.push_back(ListEntry("detectportal.firefox.com"));
    blacklist.push_back(ListEntry("connectivitycheck.gstatic.com"));
    blacklist.push_back(ListEntry("connectivitycheck.android.com"));
    blacklist.push_back(ListEntry("clients1.google.com"));
    blacklist.push_back(ListEntry("clients3.google.com"));
    blacklist.push_back(ListEntry("captive.apple.com"));

    connect(&serversock, &QUdpSocket::readyRead, this, &SmallDNSServer::processDNSRequests);
    connect(&clientsock, &QUdpSocket::readyRead, this, &SmallDNSServer::processLookups);
    dnscrypt = new DNSCrypt();
    if(dnscrypt)
        connect(dnscrypt, &DNSCrypt::decryptedLookupDoneSendResponseNow, this, &SmallDNSServer::decryptedLookupDoneSendResponseNow);
}

bool SmallDNSServer::startServer(QHostAddress address, quint16 port, bool reuse)
{ 
    return serversock.bind(address, port, reuse ? QUdpSocket::ReuseAddressHint : QUdpSocket::DefaultForPlatform);
}

void SmallDNSServer::clearDNSCache()
{
    cachedDNSResponses.clear();
    qDebug() << "Local DNS cache cleared!";
}

void SmallDNSServer::deleteEntriesFromCache(std::vector<ListEntry> entries)
{
    DNSInfo cmp;
    size_t deletionSize = entries.size();
    qDebug() << "# cached:" << cachedDNSResponses.size() << "# deleting:" << deletionSize;
    for(size_t x = 0; x < deletionSize; x++)
    {
        cmp.domainString = entries[x].hostname;
        cmp.question.qtype = entries[x].ip;

        std::remove(cachedDNSResponses.begin(), cachedDNSResponses.end(), cmp);
    }

    qDebug() << "Deleting...";
    cachedDNSResponses.erase(cachedDNSResponses.end() - deletionSize, cachedDNSResponses.end());
}

void SmallDNSServer::determineDoHDoTLSProviders()
{
    //When using only DoH and DoTLS (v2, v3) providers, a dedicated v1 DNSCrypt provider is used to resolve their hosts,
    //then DoH and DoTLS providers can be used without any issue.
    //QSslSocket::connectToHostEncrypted only takes a hostname, and when YourFriendlyDNS is set as system dns
    //it uses this server to try and resolve it, which I solved by using a dedicated v1 provider when that's happening.
    v2and3Providers.clear();
    for(QString &p : realdns)
    {
        if(p.contains("sdns://"))
        {
            DNSCryptProvider provider(p.toUtf8());
            if(provider.protocolVersion == 2 || provider.protocolVersion == 3)
                v2and3Providers.append(provider.hostname);
        }
    }
}

QString SmallDNSServer::selectRandomDNSServer()
{
    bool hasDNSProviders = false;
    for(QString &i : realdns)
    {
        if(!i.contains("sdns://"))
        {
            hasDNSProviders = true;
            break;
        }
    }

    if(!hasDNSProviders)
    {
        realdns.append("208.67.222.222:53");
        realdns.append("208.67.220.220:53");
    }

    for(int x = 0; ; x++)
    {
        QString randomServer = realdns[QRandomGenerator::global()->bounded(realdns.size())];

        if(!randomServer.contains("sdns://"))
            return randomServer;

        if(x > 100000)
            break;
    }

    return "208.67.222.222:53";
}

QString SmallDNSServer::selectRandomDNSCryptServer()
{
    QString oneProvider;
    bool hasDNSCryptProviders = false;
    quint32 providerCount = 0;
    for(QString &i : realdns)
    {
        if(i.contains("sdns://"))
        {
            oneProvider = i;
            hasDNSCryptProviders = true;
            providerCount++;
        }
    }
    if(!hasDNSCryptProviders)
    {
        realdns.append("sdns://AQAAAAAAAAAADjIwOC42Ny4yMjAuMjIwILc1EUAgbyJdPivYItf9aR6hwzzI1maNDL4Ev6vKQ_t5GzIuZG5zY3J5cHQtY2VydC5vcGVuZG5zLmNvbQ");
        return realdns.last();
    }
    else if(providerCount == 1)
        return oneProvider;

    for(size_t x = 0; ; x++)
    {
        QString randomServer = realdns[QRandomGenerator::global()->bounded(realdns.size())];

        if(randomServer.contains("sdns://"))
        {
            qDebug() << "Selected:" << randomServer;
            return randomServer;
        }

        if(x > 100000)
            break;
    }
    return "sdns://AQAAAAAAAAAADjIwOC42Ny4yMjAuMjIwILc1EUAgbyJdPivYItf9aR6hwzzI1maNDL4Ev6vKQ_t5GzIuZG5zY3J5cHQtY2VydC5vcGVuZG5zLmNvbQ";
}

bool SmallDNSServer::weDoStillHaveAConnection()
{
    if(inTimeout == 0)
    {
        if(!sendrecvFlag && responseLastReceivedTime.secsTo(requestLastSentTime) > 30)
        {
            timeoutInferencePeriod = QDateTime::currentDateTime().addSecs(30);
            inTimeout = 1;
        }
    }
    else if(inTimeout > 0)
    {
        if(inTimeout == 1)
        {
            if(QDateTime::currentDateTime() > timeoutInferencePeriod && !sendrecvFlag && responseLastReceivedTime.secsTo(requestLastSentTime) > 60)
            {
                timeoutEnd = QDateTime::currentDateTime().addSecs(120);
                qDebug() << "Haven't received responses for the last 60 seconds... Let's slow down... Taking a two minute timeout.";
                inTimeout = 2;
                //Now firmly in a timeout
            }
        }
        if(QDateTime::currentDateTime() > timeoutEnd || sendrecvFlag) //Only unless a response comes in of one already sent while waiting it out
        {
            responseLastReceivedTime = requestLastSentTime = QDateTime::currentDateTime();
            inTimeout = 0;
            emit deleteObjectsTheresNoResponseFor();
            return true;
        }
        return false;
    }
    return true;
}

void SmallDNSServer::processDNSRequests()
{
    QByteArray datagram;
    QHostAddress sender;
    quint16 senderPort;
    DNSInfo dns;

    while(serversock.hasPendingDatagrams())
    {
        datagram.resize(serversock.pendingDatagramSize());
        serversock.readDatagram(datagram.data(), datagram.size(), &sender, &senderPort);
        parseRequest(datagram, dns);
        if(!dns.isValid) continue;

        bool shouldCacheDomain, useDedicatedDNSCryptProviderToResolveV2And3Hosts = false;
        quint32 customIP = ipToRespondWith;
        std::string domain = (char*)dns.domainString.toUtf8().data();
        if(whitelistmode)
        {
            ListEntry *whiteListed = getListEntry(domain, TYPE_WHITELIST);
            if(whiteListed)
            {
                qDebug() << "Matched WhiteList!" << whiteListed->hostname << "to:" << dns.domainString;
                //It's whitelist mode and in the whitelist, so it should return a real IP! Unless you've manually specified an IP
                if(whiteListed->ip != 0)
                    customIP = whiteListed->ip;
            }
            shouldCacheDomain = (whiteListed != nullptr);
        }
        else
        {
            ListEntry *blackListed = getListEntry(domain, TYPE_BLACKLIST);
            if(blackListed)
            {
                qDebug() << "Matched BlackList!" << blackListed->hostname << "to:" << dns.domainString;
                //It's blacklist mode and in the blacklist, so it should return your custom IP! And your manually specified one if you did specify a particular one
                if(blackListed->ip != 0)
                    customIP = blackListed->ip;
            }
            shouldCacheDomain = (blackListed == nullptr);
        }
        if(shouldCacheDomain)
        {
            //Trying to exclude local hostnames from leaking
            shouldCacheDomain = (dns.domainString.contains(".") && !dns.domainString.endsWith("in-addr.arpa") && !dns.domainString.endsWith(".lan"));

            for(QString &provider : v2and3Providers)
            {
                if(provider == dns.domainString)
                {
                    useDedicatedDNSCryptProviderToResolveV2And3Hosts = true;
                    break;
                }
            }
        }

        //Rewritten and shortened
        if(!shouldCacheDomain || initialMode)
        {
            if(blockmode_returnlocalhost)
            {
                qDebug() << "Returning custom IP:" << QHostAddress(customIP).toString() << "for domain:" << dns.domainString;
                morphRequestIntoARecordResponse(datagram, customIP, dns.answeroffset, dnsTTL);
                serversock.writeDatagram(datagram, sender, senderPort);
                emit queryRespondedTo(ListEntry(dns.domainString, customIP));
            }
            else
                emit queryRespondedTo(ListEntry(dns.domainString));
        }
        else if(shouldCacheDomain)
        {
            DNSInfo *cached = getCachedEntry(dns.domainString, dns.question.qtype);
            if(cached)
                shouldCacheDomain = (QDateTime::currentDateTime() > cached->expiry);

            if(shouldCacheDomain)
            {
                if(!weDoStillHaveAConnection()) return;

                qDebug() << "Caching this domain->" << dns.domainString;
                if(cached) //If cached, update the expiry now, even though we're about to update it again in a moment
                    cached->expiry = QDateTime::currentDateTime().addSecs(cachedMinutesValid * 60);

                //Here's where we forward the received request to a real dns server, if not cached yet or its time to update the cache for this domain
                //Only executes if the domain is whitelisted or not blacklisted (depending on which mode you're using)

                dns.sender = sender;
                dns.senderPort = senderPort;
                dns.ttl = dnsTTL;

                if(dnscryptEnabled)
                {
                    qDebug() << "Making encrypted DNS request type:" << dns.question.qtype << "for domain:" << dns.domainString << "request id:" << dns.header.id << "datagram:" << datagram;
                    if(useDedicatedDNSCryptProviderToResolveV2And3Hosts)
                    {
                        dnscrypt->setProvider(dedicatedDNSCrypter);
                        qDebug() << "Using dedicated DNSCrypt provider to resolve DoH/DoTLS provider's host:" << dns.domainString;
                    }
                    else
                        dnscrypt->setProvider(selectRandomDNSCryptServer());

                    dnscrypt->makeEncryptedRequest(dns);
                }
                else
                {
                    qDebug() << "Making DNS request type:" << dns.question.qtype << "for domain:" << dns.domainString << "request id:" << dns.header.id << "datagram:" << datagram;
                    QString server = selectRandomDNSServer();
                    quint16 serverPort = DNSInfo::extractPort(server);
                    if(serverPort == 0 || serverPort == 443) serverPort = 53;
                    clientsock.writeDatagram(datagram, QHostAddress(server), serverPort);
                }

                InitialResponse *ir = new InitialResponse(dns);
                if(ir)
                {
                    connect(this, &SmallDNSServer::lookupDoneSendResponseNow, ir, &InitialResponse::lookupDoneSendResponseNow);
                    connect(this, &SmallDNSServer::deleteObjectsTheresNoResponseFor, ir, &InitialResponse::deleteObjectsTheresNoResponseFor);
                }
                requestLastSentTime = QDateTime::currentDateTime();
                sendrecvFlag = 0;
            }
            else if(cached)
            {
                if(dns.question.qtype == DNS_TYPE_A)
                {
                    if(cached->ipaddresses.size() == 0) cached->ipaddresses.push_back(ipToRespondWith);
                    //Let's use our cached IPs, and morph this request into a response containing them as appended dns answers
                    morphRequestIntoARecordResponse(datagram, cached->ipaddresses, dns.answeroffset, dnsTTL);
                    serversock.writeDatagram(datagram, sender, senderPort);
                    emit queryRespondedTo(ListEntry(dns.domainString, cached->ipaddresses[0]));
                    qDebug() << "Cached IPs returned! (first one):" << QHostAddress(cached->ipaddresses[0]) << "for domain:" << dns.domainString;
                }
                else
                {
                    *(quint16*)cached->res.data() = *(quint16*)dns.req.data();
                    serversock.writeDatagram(cached->res, sender, senderPort);
                    qDebug() << "Cached other record returned! of type:" << cached->question.qtype << "for domain:" << dns.domainString;
                }
            }
        }
    }
}

void SmallDNSServer::parseAndRespond(QByteArray &datagram, DNSInfo &dns)
{
    parseResponse(datagram, dns);

    if(dns.isValid && dns.isResponse)
    {
        if(!dns.hasIPs && dns.question.qtype == DNS_TYPE_A)
        {
            if(dns.header.rcode == RCODE_NXDOMAIN || dns.header.rcode == RCODE_YXDOMAIN || dns.header.rcode == RCODE_XRRSET)
            {
                qDebug() << "For:" << dns.domainString << "NXDOMAIN (Non eXistent domain) or similar response code received, redirecting immediately to custom ip!";
                dns.ipaddresses.push_back(ipToRespondWith);
                dns.hasIPs = true;
                emit lookupDoneSendResponseNow(dns, &serversock);
            }
        }
        else
        {
            emit lookupDoneSendResponseNow(dns, &serversock);
        }

        DNSInfo *cached = getCachedEntry(dns.domainString, dns.question.qtype);
        if(cached)
        {
            //Update the cached entry
            dns.expiry = QDateTime::currentDateTime().addSecs(cachedMinutesValid * 60);
            *cached = dns;
            qDebug() << "Updated cache of record type:" << dns.question.qtype << "for domain:" << dns.domainString << "with new expiry:" << dns.expiry;
        }
        else
        {
            //Or create the cache entry initially
            dns.expiry = QDateTime::currentDateTime().addSecs(cachedMinutesValid * 60);
            cachedDNSResponses.push_back(dns);
        }

        if(dns.hasIPs && dns.question.qtype == DNS_TYPE_A)
            emit queryRespondedTo(ListEntry(dns.domainString, dns.ipaddresses[0]));
    }
    responseLastReceivedTime = QDateTime::currentDateTime();
    sendrecvFlag = 1;
}

void SmallDNSServer::decryptedLookupDoneSendResponseNow(QByteArray decryptedResponse, DNSInfo &dns)
{
    parseAndRespond(decryptedResponse, dns);
}

void SmallDNSServer::processLookups()
{
    QByteArray datagram;
    QHostAddress sender;
    quint16 senderPort;
    DNSInfo dns;

    while(clientsock.hasPendingDatagrams())
    {
        datagram.resize(clientsock.pendingDatagramSize());
        clientsock.readDatagram(datagram.data(), datagram.size(), &sender, &senderPort);
        parseAndRespond(datagram, dns);
    }
}

ListEntry* SmallDNSServer::getListEntry(const std::string &tame, int listType)
{
    if(listType == TYPE_WHITELIST)
    {
        for(ListEntry &whiteListed : whitelist)
        {
            std::string wild = whiteListed.hostname.toUtf8().data();
            if(GeneralTextCompare((char*)tame.c_str(), (char*)wild.c_str()))
            {
                return &whiteListed;
            }
        }
    }
    else if(listType == TYPE_BLACKLIST)
    {
        for(ListEntry &blackListed : blacklist)
        {
            std::string wild = blackListed.hostname.toUtf8().data();
            if(GeneralTextCompare((char*)tame.c_str(), (char*)wild.c_str()))
            {
                return &blackListed;
            }
        }
    }
    return nullptr;
}

DNSInfo* SmallDNSServer::getCachedEntry(const QString &byDomain, quint16 andType)
{
    size_t cachedSize = cachedDNSResponses.size();
    for(size_t i = 0; i < cachedSize; i++)
    {
        DNSInfo *pDNS = &cachedDNSResponses[i];

        if(pDNS->domainString == byDomain && pDNS->question.qtype == andType)
            return pDNS;
    }

    return nullptr;
}

bool SmallDNSServer::interpretHeader(const QByteArray &dnsmessage, DNSInfo &dns)
{
    if(dnsmessage.size() >= DNS_HEADER_SIZE)
    {
        memcpy(&dns.header, dnsmessage.data(), DNS_HEADER_SIZE);
        //correcting values because of network byte order...
        dns.header.id = qFromBigEndian(dns.header.id);
        dns.header.q_count = qFromBigEndian(dns.header.q_count);
        dns.header.ans_count = qFromBigEndian(dns.header.ans_count);
        dns.header.auth_count = qFromBigEndian(dns.header.auth_count);
        dns.header.add_count = qFromBigEndian(dns.header.add_count);

        dns.isResponse = dns.header.QUERY_RESPONSE_FLAG;
        dns.isValid = true;
    }
    else
        dns.isValid = false;

    return dns.isValid;
}

void SmallDNSServer::parseRequest(const QByteArray &dnsrequest, DNSInfo &dns)
{
    if(!interpretHeader(dnsrequest, dns))
        return;

    if(dns.header.QUERY_RESPONSE_FLAG != 0)
    {
        dns.isValid = false;
        return;
    }

    dns.req = dnsrequest;
    getDomainString(dnsrequest, dns);

    //qDebug() << "for:" << dns.domainString << "parsed request header id:" << dns.header.id << "qcount:" << dns.header.q_count << "answer count:" << dns.header.ans_count
    //         << "auth count:" << dns.header.auth_count << "add count:" << dns.header.add_count;
}

void SmallDNSServer::parseResponse(const QByteArray &dnsresponse, DNSInfo &dns)
{
    if(!interpretHeader(dnsresponse, dns))
        return;

    if(dns.header.QUERY_RESPONSE_FLAG != 1)
    {
        dns.isValid = false;
        return;
    }

    dns.res = dnsresponse;
    getDomainString(dnsresponse, dns);
    getHostAddresses(dnsresponse, dns);

    //qDebug() << "for:" << dns.domainString << "parsed response header id:" << dns.header.id << "qcount:" << dns.header.q_count << "answer count:" << dns.header.ans_count
    //         << "auth count:" << dns.header.auth_count << "add count:" << dns.header.add_count << "whole response:" << dns.res;
}

QString SmallDNSServer::getDomainString(const QByteArray &dnsmessage, DNSInfo &dns)
{
    QString fullname;
    const char *ptr = &dnsmessage.data()[DNS_HEADER_SIZE], *ptr_origin = &dnsmessage.data()[0];
    const char *ptr_end = &dnsmessage.data()[dnsmessage.size()];
    quint8 len;
    char partialname[64];
    do
    {
        len = *ptr++;
        if(len == 0) break;
        if(len > 63 || (ptr + len) >= ptr_end) { dns.isValid = false; return fullname; }
        memcpy(partialname, ptr, len);
        partialname[len] = 0;
        fullname += partialname;

        ptr += len;
        if(*ptr != 0) fullname += ".";
    }
    while(len != 0);

    dns.domainString = fullname.toLower();

    if(ptr < ptr_end)
        dns.question.qtype = qFromBigEndian(*(quint16*)ptr);
    ptr += 2;
    if(ptr < ptr_end)
        dns.question.qclass = qFromBigEndian(*(quint16*)ptr);
    ptr += 2;

    dns.answeroffset = (ptr - ptr_origin);

    //qDebug() << "got domain name string:" << fullname
    //         << "qtype:" << dns.question.qtype << "qclass:" << dns.question.qclass
    //         << "isresponse:" << dns.isResponse << "answer offset:" << dns.answeroffset;

    return fullname;
}

void SmallDNSServer::getHostAddresses(const QByteArray &dnsresponse, DNSInfo &dns)
{
    dns.hasIPs = false;
    if(!dns.isResponse || dns.question.qtype != DNS_TYPE_A) return; //if not a response and containing an A record, then there's no IPs here to grab...

    ANSWER answer;
    const char *ptr = &dnsresponse.data()[dns.answeroffset];
    const char *ptr_end = &dnsresponse.data()[dnsresponse.size()];

    for(quint16 i = 0; i < dns.header.ans_count; i++)
    {
        if((ptr + DNS_HEADER_SIZE) >= ptr_end)
            break;

        answer.name = qFromBigEndian(*(quint16*)ptr);
        ptr += 2;
        answer.type = qFromBigEndian(*(quint16*)ptr);
        ptr += 2;
        answer.rclass = qFromBigEndian(*(quint16*)ptr);
        ptr += 2;
        answer.ttl = qFromBigEndian(*(quint32*)ptr);
        ptr += 4;
        answer.rdlength = qFromBigEndian(*(quint16*)ptr);
        ptr += 2;

        //qDebug() << "Interpreted answer name:" << answer.name << "type:" << answer.type << "rclass:" << answer.rclass << "ttl:" << answer.ttl << "rdlength:" << answer.rdlength;

        quint32 ip;
        if(answer.type == DNS_TYPE_A && answer.rdlength == 4) //if it's an A record which should be 4 bytes
        {
            memcpy(&ip, ptr, 4);
            ip = qFromBigEndian(ip);

            qDebug() << "Got IP:" << QHostAddress(ip).toString() << "for domain:" << dns.domainString;
            dns.ipaddresses.push_back(ip);
            dns.hasIPs = true;
        }

        if((ptr + answer.rdlength) < ptr_end)
            ptr += answer.rdlength;
        else
            break;
    }
}

//Thanks Kirk!
/*By Kirk J. Krauss, August 26, 2008
A simple wildcard text-matching algorithm in a single while loop */

//This function compares text strings, one of which can have wildcards ('*').
bool GeneralTextCompare(
        char * pTameText,             // A string without wildcards
        char * pWildText,             // A (potentially) corresponding string with wildcards
        bool bCaseSensitive,  // By default, match on 'X' vs 'x'
        char cAltTerminator    // For function names, for example, you can stop at the first '('
)
{
        bool bMatch = true;
        char * pAfterLastWild = 0; // The location after the last '*', if we’ve encountered one
        char * pAfterLastTame = 0; // The location in the tame string, from which we started after last wildcard
        char t, w;

        // Walk the text strings one character at a time.
        for(;;)
        {
                t = *pTameText;
                w = *pWildText;

                //qDebug() << "tame:" << t << "wild:" << w;

                // How do you match a unique text string?
                if (!t || t == cAltTerminator)
                {
                        // Easy: unique up on it!
                        if (!w || w == cAltTerminator)
                        {
                                break;                                   // "x" matches "x"
                        }
                        else if (w == '*')
                        {
                                pWildText++;
                                continue;                           // "x*" matches "x" or "xy"
                        }
                        else if (pAfterLastTame)
                        {
                                if (!(*pAfterLastTame) || *pAfterLastTame == cAltTerminator)
                                {
                                        bMatch = false;
                                        break;
                                }
                                pTameText = pAfterLastTame++;
                                pWildText = pAfterLastWild;
                                continue;
                        }

                        bMatch = false;
                        break;                                           // "x" doesn't match "xy"
                }
                else
                {
                        if (!bCaseSensitive)
                        {
                                // Lowercase the characters to be compared.
                                if (t >= 'A' && t <= 'Z')
                                {
                                        t += ('a' - 'A');
                                }

                                if (w >= 'A' && w <= 'Z')
                                {
                                        w += ('a' - 'A');
                                }
                        }

                        // How do you match a tame text string?
                        if (t != w)
                        {
                                // The tame way: unique up on it!
                                if (w == '*')
                                {
                                        pAfterLastWild = ++pWildText;
                                        pAfterLastTame = pTameText;
                                        w = *pWildText;

                                        if (!w || w == cAltTerminator)
                                        {
                                                break;                           // "*" matches "x"
                                        }
                                        continue;                           // "*y" matches "xy"
                                }
                                else if (pAfterLastWild)
                                {
                                        if (pAfterLastWild != pWildText)
                                        {
                                                pWildText = pAfterLastWild;
                                                w = *pWildText;

                                                if (!bCaseSensitive && w >= 'A' && w <= 'Z')
                                                {
                                                        w += ('a' - 'A');
                                                }

                                                if (t == w)
                                                {
                                                        pWildText++;
                                                }
                                        }

                                        pTameText++;
                                        continue;                           // "*sip*" matches "mississippi"
                                }
                                else
                                {
                                        bMatch = false;
                                        break;                                   // "x" doesn't match "y"
                                }
                        }
                }

                pTameText++;
                pWildText++;
                //qDebug() << "t:" << pTameText << "w:" << pWildText;
        }

        return bMatch;
}
