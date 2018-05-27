#ifndef SMALLDNSSERVER_H
#define SMALLDNSSERVER_H

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

#include <QNetworkDatagram>
#include <QNetworkInterface>
#include <QDnsLookup>
#include <QHostAddress>
#include <QHostInfo>
#include <QtEndian>
#include <QtCore>
#include <QProcess>
#include "androidsuop.h"
#include "initialresponse.h"
#include "dnscrypt.h" //Including our DNSCrypt class and helpers, giving us DNSCrypt protocol version 1,2,3 support!

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

/* GeneralTextCompare By Kirk J. Krauss, August 26, 2008

A simple wildcard text-matching algorithm in a single while loop */
bool GeneralTextCompare(
        char * pTameText,             // A string without wildcards
        char * pWildText,             // A (potentially) corresponding string with wildcards
        bool bCaseSensitive = false,  // By default, match on 'X' vs 'x'
        char cAltTerminator = '\0'    // For function names, for example, you can stop at the first '('
);

class SmallDNSServer : public QObject
{
    Q_OBJECT
public:
    explicit SmallDNSServer(QObject *parent = nullptr);
    bool startServer(QHostAddress address = QHostAddress::AnyIPv4, quint16 port = 53, bool reuse = false);
    QString getDomainString(const QByteArray &dnsmessage, DNSInfo &dns);
    void determineDoHDoTLSProviders();

    bool whitelistmode, blockmode_returnlocalhost, initialMode, autoTTL, dnscryptEnabled, sendrecvFlag;
    QDateTime requestLastSentTime, responseLastReceivedTime, timeoutInferencePeriod, timeoutEnd;
    Q_IPV6ADDR ipv6ToRespondWith;
    quint32 ipToRespondWith, cachedMinutesValid, dnsTTL, inTimeout;
    quint64 numSentRequests, numReceivedResponses;
    QString dedicatedDNSCrypter;
    QVector<ListEntry> whitelist,blacklist;
    QVector<QString> realdns, v2and3Providers;
    QVector<quint32> listeningIPs;
    QVector<Q_IPV6ADDR> listeningIPv6s;
    std::vector<DNSInfo> cachedDNSResponses;
    QUdpSocket serversock;
    DNSCrypt *dnscrypt;

private:
    ListEntry* getListEntry(const std::string &tame, int listType);
    DNSInfo* getCachedEntry(const QString &byDomain, quint16 andType);
    void parseAndRespond(QByteArray &datagram, DNSInfo &dns);
    bool interpretHeader(const QByteArray &dnsmessage, DNSInfo &dns);
    void parseRequest(const QByteArray &dnsrequest, DNSInfo &dns);
    void parseResponse(const QByteArray &dnsresponse, DNSInfo &dns);
    void getHostAddresses(const QByteArray &dnsresponse, DNSInfo &dns);
    QString selectRandomDNSServer();
    QString selectRandomDNSCryptServer();
    bool weDoStillHaveAConnection();
    QUdpSocket clientsock;

signals:
    void queryRespondedTo(ListEntry responded);
    void lookupDoneSendResponseNow(DNSInfo &dns, QUdpSocket *serversocket);
    void deleteObjectsTheresNoResponseFor();

public slots:
    void clearDNSCache();
    void deleteEntriesFromCache(std::vector<ListEntry> entries);
    void decryptedLookupDoneSendResponseNow(QByteArray decryptedResponse, DNSInfo &dns);

private slots:
    void processDNSRequests();
    void processLookups();
};

#endif // SMALLDNSSERVER_H
