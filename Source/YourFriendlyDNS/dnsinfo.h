#ifndef DNSINFO_H
#define DNSINFO_H

#include <QHostAddress>
#include <QDateTime>
#include <QString>

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
