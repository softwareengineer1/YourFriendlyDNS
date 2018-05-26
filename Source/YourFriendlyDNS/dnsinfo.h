#ifndef DNSINFO_H
#define DNSINFO_H

#include <QHostAddress>
#include <QDateTime>
#include <QString>

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

#define DNS_HEADER_SIZE 12
#define DNS_TYPE_A 1
#define DNS_TYPE_AAAA 28
#define DNS_TYPE_TXT 16

#define RCODE_NOERROR 0
#define RCODE_FMTERROR 1
#define RCODE_SERVFAIL 2
#define RCODE_NXDOMAIN 3
#define RCODE_NOTIMPL 4
#define RCODE_REFUSED 5
#define RCODE_YXDOMAIN 6
#define RCODE_XRRSET 7
#define RCODE_NOTAUTH 8
#define RCODE_NOTZONE 9

// DNS header structure : 12 bytes
struct DNS_HEADER
{
    unsigned short id; // identification number

    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char AUTHORITATIVE_ANSWER_FLAG :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char QUERY_RESPONSE_FLAG :1; // query/response flag

    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char RECURSION_AVAILABLE_FLAG :1; // recursion available

    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};

struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};

struct ANSWER
{
    quint16 name;
    quint16 type;
    quint16 rclass;
    quint32 ttl;
    quint16 rdlength;
    //rdata
};

class DNSInfo
{
public:
    DNSInfo()
    {
        memset(&header, 0, sizeof(header));
        memset(&question, 0, sizeof(question));
        answeroffset = 0;
        senderPort = 0;
        ttl = 0;
        isValid = isResponse = hasIPs = false;
        expiry = QDateTime::currentDateTime();
    }
    DNSInfo(const DNSInfo &info)
    {
        copyDNSInfoFrom(info);
    }
    DNSInfo operator=(const DNSInfo &info)
    {
        copyDNSInfoFrom(info);
        return *this;
    }
    bool operator==(const DNSInfo &info)
    {
        return (this->domainString == info.domainString && this->question.qtype == info.question.qtype);
    }
    void copyDNSInfoFrom(const DNSInfo &info)
    {
        memcpy(&this->header, &info.header, sizeof(header));
        memcpy(&this->question, &info.question, sizeof(question));
        this->domainString = info.domainString;
        this->answeroffset = info.answeroffset;
        this->ttl = info.ttl;
        this->isValid = info.isValid;
        this->isResponse = info.isResponse;
        this->hasIPs = info.hasIPs;
        this->ipaddresses = info.ipaddresses;
        this->expiry = info.expiry;
        this->req = info.req;
        this->res = info.res;
        this->sender = info.sender;
        this->senderPort = info.senderPort;
    }
    static quint16 extractPort(QString &addr)
    {
        if(addr.size() == 0) return 443;
        if(!addr.contains(".") && !addr.contains("[")) { quint16 port = addr.toInt(); addr.clear(); return port; }
        if(addr.data()[0] == '[')
        {
            addr.remove(0, 1);
            int portOffset = addr.lastIndexOf("]:");
            if(portOffset != -1)
            {
                QString ipv6Port = addr.right(addr.size() - (portOffset + 2));
                addr.truncate(portOffset);
                return ipv6Port.toInt();
            }
            else
            {
                addr.truncate(addr.size() - 1);
                return 443;
            }
        }
        else
        {
            int portOffset = addr.lastIndexOf(":");
            if(portOffset != -1)
            {
                QString ipv4Port = addr.right(addr.size() - (portOffset + 1));
                addr.truncate(portOffset);
                return ipv4Port.toInt();
            }
            else
                return 443;
        }
    }
    DNS_HEADER header;
    QUESTION question;
    QString domainString;
    quint16 senderPort;
    quint32 answeroffset, ttl;
    bool isValid, isResponse, hasIPs;
    std::vector<quint32> ipaddresses;
    QDateTime expiry;
    QByteArray req, res;
    QHostAddress sender;
};

class ListEntry
{
public:
    QString hostname;
    quint32 ip;
    ListEntry() { ip = 0; }
    ListEntry(const QString &host, quint32 address = 0)
    {
        hostname = host;
        ip = address;
    }
};

#define TYPE_WHITELIST 1
#define TYPE_BLACKLIST 2

#endif // DNSINFO_H
