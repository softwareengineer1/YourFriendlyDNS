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

SmallDNSServer::SmallDNSServer(QObject *parent) : QObject(parent)
{
    connect(&serversock, SIGNAL(readyRead()), this, SLOT(processDNSRequests()), Qt::DirectConnection);
    connect(&clientsock, SIGNAL(readyRead()), this, SLOT(processLookups()), Qt::DirectConnection);
    ipToRespondWith = QHostAddress("127.0.0.1").toIPv4Address();
    serverPortForAndroid = 5333; //On android I can't bind as root to port 53, so use a high enough port and iptables as root to redirect 53 -> 5354 instead
    cachedMinutesValid = 5;

    whitelistmode = initialMode = blockmode_returnlocalhost = true;
    //default is whitelist mode, with just these two entries to get you started!
    whitelist.push_back(ListEntry("*startpage.com"));
    whitelist.push_back(ListEntry("*gbatemp.net"));

    //Just in case someone switches to blacklist right away and disables initial mode without setting it up
    //This initial default setup should at least help avert disaster, and this demonstrates that it supports wild cards!
    //*.srv.nintendo.net
    //*.d4c.nintendo.net
    //*.eshop.nintendo.net
    blacklist.push_back(ListEntry("*srv.nintendo.net"));
    blacklist.push_back(ListEntry("*d4c.nintendo.net"));
    blacklist.push_back(ListEntry("*eshop.nintendo.net"));
}

SmallDNSServer::~SmallDNSServer()
{
#ifdef Q_OS_ANDROID
    QProcess su;
    su.start("su");
    su.waitForStarted();

    su.write(QString("iptables -D INPUT -p udp --dport %1 -j ACCEPT\n").arg(serverPortForAndroid).toUtf8());
    su.write(QString("iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports %1\n").arg(serverPortForAndroid).toUtf8());
    su.closeWriteChannel();
#endif
}

bool SmallDNSServer::startServer(QHostAddress address, quint16 port, bool reuse)
{
    Q_UNUSED(port);
#ifdef Q_OS_ANDROID

    //Run su, enable ipv4 forwarding, and do iptables redirect from port 53(dns) to 5354 (where this server is binded on android)
    QProcess su;
    su.start("su"); //First time running it, accept the root prompt
    if(!su.waitForStarted())
        return false;

    su.write("sysctl -w net.ipv4.ip_forward=1\n");
    su.write(QString("iptables -A INPUT -p udp --dport %1 -j ACCEPT\n").arg(serverPortForAndroid).toUtf8());
    su.write(QString("iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports %1\n").arg(serverPortForAndroid).toUtf8());
    su.closeWriteChannel();

    if(!su.waitForFinished())
        return false;

    return serversock.bind(address, serverPortForAndroid, reuse ? QUdpSocket::ReuseAddressHint : QUdpSocket::DefaultForPlatform);
#else
    return serversock.bind(address, port, reuse ? QUdpSocket::ReuseAddressHint : QUdpSocket::DefaultForPlatform);
#endif
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

    return QHostAddress(realdns[rand() % realdns.size()]);
}

void SmallDNSServer::processDNSRequests()
{
    QByteArray datagram;
    QHostAddress sender;
    quint16 senderPort;
    DNSInfo dns;
    bool shouldReturnCustomIP = whitelistmode;
    quint32 customIP = ipToRespondWith;

    while(serversock.hasPendingDatagrams())
    {
        datagram.resize(serversock.pendingDatagramSize());
        serversock.readDatagram(datagram.data(), datagram.size(), &sender, &senderPort);
        parseRequest(datagram, dns);

        if(!dns.isValid) continue;
        bool cacheNewIPForDomain = true;
        std::string tame = (char*)dns.domainString.toUtf8().data();
        if(whitelistmode)
        {
            bool whitelisted = false;
            for(ListEntry &whitelistedDomain : whitelist)
            {
                std::string wild = whitelistedDomain.hostname.toUtf8().data();
                ////if(dns.domainString == whitelistedDomain.hostname)
                if(GeneralTextCompare((char*)tame.c_str(), (char*)wild.c_str()))
                {
                    qDebug() << "Matched WhiteList!" << whitelistedDomain.hostname << "to:" << dns.domainString;
                    whitelisted = true;

                    //It's whitelist mode and in the whitelist, so it should return a real IP! Unless you've manually specified an IP
                    if(whitelistedDomain.ip == 0)
                        shouldReturnCustomIP = false;
                    else
                        customIP = whitelistedDomain.ip;
                    break;
                }
            }
            cacheNewIPForDomain = whitelisted;
        }
        else
        {
            bool notblacklisted = true;
            for(ListEntry &blacklistedDomain : blacklist)
            {
                std::string wild = blacklistedDomain.hostname.toStdString();
                //if(dns.domainString == blacklistedDomain.hostname)
                if(GeneralTextCompare((char*)tame.c_str(), (char*)wild.c_str()))
                {
                    qDebug() << "Matched BlackList!" << blacklistedDomain.hostname << "to:" << dns.domainString;
                    notblacklisted = false;
                    //It's blacklist mode and in the blacklist, so it should return your custom IP! And your manually specified one if you did specify a particular one
                    shouldReturnCustomIP = true;
                    if(blacklistedDomain.ip != 0)
                        customIP = blacklistedDomain.ip;
                    break;
                }
            }
            cacheNewIPForDomain = notblacklisted;
        }

        if(shouldReturnCustomIP || initialMode)
        {
            //For just being straight up like fk you! here's localhost!! lol or not responding at all,
            //but returning localhost is better I think, as not responding might make our dns server seem down cause it to user another if it knows another one.
            //The option is there though to use either way that works for you.
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
        else if(dns.question.qtype == 1)
        {
            if(!cachedDNSResponses.empty())
            {
                for(DNSInfo &d : cachedDNSResponses)
                {
                    //if(wildcmp(d.domainString.toStdString().c_str(), compareDomain))
                    if(d.domainString == dns.domainString)
                    {
                        cacheNewIPForDomain = (QDateTime::currentDateTime() > d.expiry);

                        if(!d.ipaddresses.empty())
                        {
                            //Let's use our cached IPs, and morph this request into a response containing them as appended dns answers
                            morphRequestIntoARecordResponse(datagram, d.ipaddresses, d.answeroffset);
                            serversock.writeDatagram(datagram, sender, senderPort);
                            emit queryRespondedTo(ListEntry(d.domainString,d.ipaddresses[0]));

                            qDebug() << "Returned cached ips (first one):" << QHostAddress(d.ipaddresses[0]) << "for domain:" << d.domainString << "stale ips?:" << cacheNewIPForDomain;
                            break;
                        }
                        else
                            break;
                    }
                }
            }

            //Here's where we forward the received request to a real dns server, if not cached yet or its time to update the cache for this domain
            //Only executes if the domain is whitelisted or not blacklisted (depending on which mode you're using)
            if(cacheNewIPForDomain)
            {
                QHostAddress realdnsserver = selectRandomDNSServer();
                qDebug() << "Making DNS request for domain:" << dns.domainString << "Using real DNS:" << realdnsserver;
                clientsock.writeDatagram(datagram, realdnsserver, 53);

                dns.req = datagram;
                dns.sender = sender;
                dns.senderPort = senderPort;
                InitialResponse *irt = new InitialResponse(dns);
                connect(this, SIGNAL(lookupDoneSendResponseNow(DNSInfo&,QUdpSocket*)), irt, SLOT(lookupDoneSendResponseNow(DNSInfo&,QUdpSocket*)), Qt::DirectConnection);
            }
        }
        else
        {
            //If it's not an A record request, but it's still a host in the whitelist/not in the blacklist, then let's handle it anyway to be complete
            //NOTE: Unlike for A records I don't interpret them fully, just proxy it (forward to real dns server, get response, and pass it back to requester)
            if(cacheNewIPForDomain)
            {
                QHostAddress realdnsserver = selectRandomDNSServer();
                qDebug() << "Making non A record request for domain:" << dns.domainString << "Using DNS Server:" << realdnsserver;
                clientsock.writeDatagram(datagram, realdnsserver, 53);

                dns.req = datagram;
                dns.sender = sender;
                dns.senderPort = senderPort;
                InitialResponse *irt = new InitialResponse(dns);
                connect(this, SIGNAL(lookupDoneSendResponseNow(DNSInfo&,QUdpSocket*)), irt, SLOT(lookupDoneSendResponseNow(DNSInfo&,QUdpSocket*)), Qt::DirectConnection);
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
            emit lookupDoneSendResponseNow(dns, &serversock);

            if(!dns.ipaddresses.empty()) //my cache is only for A record responses containing ip addresses, if there's no ips it's not the right response to cache
            {
                dns.expiry = QDateTime::currentDateTime().addSecs(cachedMinutesValid * 60);
                //Update cache if already exists
                for(size_t i = 0; i < cachedDNSResponses.size(); i++)
                {
                    //qDebug() << "Looking in cache for:" << dns.domainString << cachedDNSResponses[i].domainString;
                    if(cachedDNSResponses[i].domainString == dns.domainString)
                    {
                        //qDebug() << "Updating cache for:" << dns.domainString << "new expiry:" << dns.expiry;
                        cachedDNSResponses[i] = dns;
                        emit queryRespondedTo(ListEntry(dns.domainString,dns.ipaddresses[0]));
                        return;
                    }
                }
                //Or just add it initially
                cachedDNSResponses.push_back(dns);
                emit queryRespondedTo(ListEntry(dns.domainString,dns.ipaddresses[0]));
            }
        }
    }
}

void SmallDNSServer::parseRequest(QByteArray &dnsrequest, DNSInfo &dns)
{
    if(dnsrequest.size() < 12)
    {
        dns.isValid = false;
        return;
    }

    char *ptr = dnsrequest.data();
    /*if((ptr[2] & 0x80) != 0)
    {
        dns.isValid = false;
        return;
    }*/

    dns.isValid = true;

    memcpy(&dns.header, ptr, 12);
    //correcting values because of network byte order...
    dns.header.id = qFromBigEndian(dns.header.id);
    dns.header.q_count = qFromBigEndian(dns.header.q_count);
    dns.header.ans_count = qFromBigEndian(dns.header.ans_count);
    dns.header.auth_count = qFromBigEndian(dns.header.auth_count);
    dns.header.add_count = qFromBigEndian(dns.header.add_count);

    getDomainString(dnsrequest,dns);

    //qDebug() << "for:" << dns.domainString << "parsed request header id:" << dns.header.id << "qcount:" << dns.header.q_count << "answer count:" << dns.header.ans_count
    //         << "auth count:" << dns.header.auth_count << "add count:" << dns.header.add_count;
}

void SmallDNSServer::parseResponse(QByteArray &dnsresponse, DNSInfo &dns)
{
    if(dnsresponse.size() < 12)
    {
        dns.isValid = false;
        return;
    }

    char *ptr = dnsresponse.data();
    /*if((ptr[2] & 0x80) == 0)
    {
        dns.isValid = false;
        return;
    }*/

    dns.isValid = dns.isResponse = true;

    memcpy(&dns.header, ptr, 12);
    //correcting values because of network byte order...
    dns.header.id = qFromBigEndian(dns.header.id);
    dns.header.q_count = qFromBigEndian(dns.header.q_count);
    dns.header.ans_count = qFromBigEndian(dns.header.ans_count);
    dns.header.auth_count = qFromBigEndian(dns.header.auth_count);
    dns.header.add_count = qFromBigEndian(dns.header.add_count);
    dns.res = dnsresponse;

    getDomainString(dnsresponse, dns);
    getHostAddresses(dnsresponse, dns);

    //qDebug() << "for:" << dns.domainString << "parsed response header id:" << dns.header.id << "qcount:" << dns.header.q_count << "answer count:" << dns.header.ans_count
    //         << "auth count:" << dns.header.auth_count << "add count:" << dns.header.add_count << "whole response:" << dns.res;
}

QString SmallDNSServer::getDomainString(const QByteArray &dnsmessage, DNSInfo &dns)
{
    QString fullname;
    char temp[64];
    quint8 *pointer = (quint8*)&dnsmessage.data()[12], *pointerorigin = (quint8*)&dnsmessage.data()[0];
    quint8 len;
    do
    {
        len = *pointer++;
        if(len == 0 || len > 63) break;
        memcpy(temp, pointer, len);
        temp[len] = 0;

        pointer += len;
        fullname += temp;
        if(*pointer != 0) fullname += ".";
    }
    while(len != 0);

    dns.domainString = fullname;

    dns.question.qtype = qFromBigEndian(*(quint16*)pointer);
    pointer += 2;
    dns.question.qclass = qFromBigEndian(*(quint16*)pointer);
    pointer += 2;

    dns.answeroffset = (pointer - pointerorigin);

    //qDebug() << "got domain name string:" << fullname
    //         << "qtype:" << dns.question.qtype << "qclass:" << dns.question.qclass
    //         << "isresponse:" << dns.isResponse << "answer offset:" << dns.answeroffset;

    return fullname;
}

void SmallDNSServer::getHostAddresses(const QByteArray &dnsresponse, DNSInfo &dns)
{
    if(!dns.isResponse || dns.question.qtype != 1) return; //if not a response and containing an A record, then there's no IPs here to grab...

    ANSWER answer;
    const char *ptr = &dnsresponse.data()[dns.answeroffset];

    for(quint16 i = 0; i < dns.header.ans_count; i++)
    {
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

        qDebug() << "Interpreted answer name:" << answer.name << "type:" << answer.type << "rclass:" << answer.rclass << "ttl:" << answer.ttl << "rdlength:" << answer.rdlength;

        quint32 ip;
        if(answer.type == 1 && answer.rdlength == 4) //if it's an A record which should be 4 bytes
        {
            memcpy(&ip, ptr, 4);
            ip = qFromBigEndian(ip);

            qDebug() << "Got IP:" << QHostAddress(ip).toString() << "for domain:" << dns.domainString;
            dns.ipaddresses.push_back(ip);
        }

        ptr += answer.rdlength;
    }
}

//Thanks Kirk!

/*By Kirk J. Krauss, August 26, 2008

A simple wildcard text-matching algorithm in a single while loop */

//This function compares text strings, one of which can have wildcards ('*').
//
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
