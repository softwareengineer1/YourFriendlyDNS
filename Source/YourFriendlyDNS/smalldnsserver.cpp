#include "smalldnsserver.h"

/* YourFriendlyDNS - A really awesome multi-platform (lin,win,mac,android) local caching and proxying dns server!
Copyright (C) 2018  softwareengineer1 @ github.com/softwareengineer1
Support my work so I can keep bringing you great free and open software!
I'm going entirely 100% free software this year in 2018 (and onwards I want to) :)
Everything I make will be released under a free software license! That's my promise!
If you want to contact me another way besides through github, insert your message into the blockchain with a BCH/BTC UTXO! ^_^
Thank you for your support!
BCH: bitcoincash:qzh3knl0xeyrzrxm5paenewsmkm8r4t76glzxmzpqs
BTC: 1279WngWQUTV56UcTvzVAnNdR3Z7qb6R8j

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
    dnsServerPort = 53; //port 53 by default android will figure it out and go 5333 by default
    httpServerPort = 80;
    cachedMinutesValid = 7;

    whitelistmode = initialMode = blockmode_returnlocalhost = true;
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

QHostAddress SmallDNSServer::selectRandomDNSServer()
{
    if(realdns.isEmpty())
    {
        realdns.append("208.67.222.222");
        realdns.append("208.67.220.220");
    }

    return QHostAddress(realdns[QRandomGenerator::global()->bounded(realdns.size())]);
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

        bool shouldCacheDomain;
        quint32 customIP = ipToRespondWith;
        std::string tame = (char*)dns.domainString.toUtf8().data(); //I think this one is better
        if(whitelistmode)
        {
            bool whitelisted = false;
            for(ListEntry &whitelistedDomain : whitelist)
            {
                std::string wild = whitelistedDomain.hostname.toUtf8().data();
                if(GeneralTextCompare((char*)tame.c_str(), (char*)wild.c_str()))
                {
                    qDebug() << "Matched WhiteList!" << whitelistedDomain.hostname << "to:" << dns.domainString << "wild:" << wild.c_str() << "tame:" << tame.c_str();
                    whitelisted = true;
                    //It's whitelist mode and in the whitelist, so it should return a real IP! Unless you've manually specified an IP
                    if(whitelistedDomain.ip != 0)
                        customIP = whitelistedDomain.ip;
                    break;
                }
            }
            shouldCacheDomain = whitelisted;
        }
        else
        {
            bool notblacklisted = true;
            for(ListEntry &blacklistedDomain : blacklist)
            {
                std::string wild = blacklistedDomain.hostname.toUtf8().data();
                if(GeneralTextCompare((char*)tame.c_str(), (char*)wild.c_str()))
                {
                    qDebug() << "Matched BlackList!" << blacklistedDomain.hostname << "to:" << dns.domainString << "wild:" << wild.c_str() << "tame:" << tame.c_str();
                    notblacklisted = false;
                    //It's blacklist mode and in the blacklist, so it should return your custom IP! And your manually specified one if you did specify a particular one
                    if(blacklistedDomain.ip != 0)
                        customIP = blacklistedDomain.ip;
                    break;
                }
            }
            shouldCacheDomain = notblacklisted;
        }
        if(shouldCacheDomain)
            shouldCacheDomain = dns.domainString.contains(".");

        //Rewritten and shortened
        if(!shouldCacheDomain || initialMode)
        {
            if(blockmode_returnlocalhost)
            {
                qDebug() << "Returning custom IP:" << QHostAddress(customIP).toString() << "for domain:" << dns.domainString;
                morphRequestIntoARecordResponse(datagram, customIP, dns.answeroffset);
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
                cached->expiry = QDateTime::currentDateTime().addSecs(cachedMinutesValid * 60);
                //Here's where we forward the received request to a real dns server, if not cached yet or its time to update the cache for this domain
                //Only executes if the domain is whitelisted or not blacklisted (depending on which mode you're using)
                qDebug() << "Making DNS request type:" << dns.question.qtype << "for domain:" << dns.domainString << "request id:" << dns.header.id << "datagram:" << datagram;
                clientsock.writeDatagram(datagram, selectRandomDNSServer(), 53);

                dns.sender = sender;
                dns.senderPort = senderPort;
                InitialResponse *ir = new InitialResponse(dns);
                connect(this, &SmallDNSServer::lookupDoneSendResponseNow, ir, &InitialResponse::lookupDoneSendResponseNow);
            }
            else if(cached)
            {
                if(dns.question.qtype == DNS_TYPE_A)
                {
                    if(cached->ipaddresses.size() == 0) cached->ipaddresses.push_back(ipToRespondWith);
                    //Let's use our cached IPs, and morph this request into a response containing them as appended dns answers
                    morphRequestIntoARecordResponse(datagram, cached->ipaddresses, cached->answeroffset);
                    serversock.writeDatagram(datagram, sender, senderPort);
                    emit queryRespondedTo(ListEntry(cached->domainString, cached->ipaddresses[0]));
                    qDebug() << "Cached IPs returned! (first one):" << QHostAddress(cached->ipaddresses[0]) << "for domain:" << cached->domainString;
                }
                else if(cached->isValid)
                {
                    *(quint16*)cached->res.data() = *(quint16*)dns.req.data();
                    serversock.writeDatagram(cached->res, sender, senderPort);
                    qDebug() << "Cached other record returned! of type:" << cached->question.qtype << "for domain:" << cached->domainString;
                }
            }
        }
    }
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
    }
}

DNSInfo* SmallDNSServer::getCachedEntry(QString byDomain, quint16 andType)
{
    size_t cachedSize = cachedDNSResponses.size();
    for(size_t i = 0; i < cachedSize; i++)
    {
        DNSInfo *pDNS = &cachedDNSResponses[i];

        if(pDNS->domainString == byDomain && pDNS->question.qtype == andType)
        {
            return pDNS;
        }
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

    dns.domainString = fullname;

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
