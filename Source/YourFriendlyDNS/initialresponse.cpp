#include "initialresponse.h"

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

void morphRequestIntoARecordResponse(QByteArray &dnsrequest, quint32 responseIP, quint32 spliceOffset, quint32 ttl)
{
    if(dnsrequest.size() >= DNS_HEADER_SIZE) //Make sure there's at least a dns header here to write to
    {
        DNS_HEADER *header = (DNS_HEADER*)dnsrequest.data();

        header->QUERY_RESPONSE_FLAG = 1; //Change from query to response
        if(header->rd == 1) //Do this so there's not even a warning about about recursion requested but not available, let's say yes if it's requested.
            header->RECURSION_AVAILABLE_FLAG = 1;
        header->ans_count = qToBigEndian((quint16)1);
        header->rcode = RCODE_NOERROR;
        // DNS Answer
        unsigned char QAnswer[] = {
            0xc0,0x0c, // 1100 0000 0000 1100 -> offset = 12
            0x00,0x01, // Type  : A
            0x00,0x01, // Class : IN
            0x00,0x01,0x51,0x80, // TTL = 86400 -> 24h
            0x00,0x04, // RD Length
            0x00,0x00,0x00,0x00 // RDATA
        };
        QAnswer[12] = (responseIP & 0xff000000) >> 24;
        QAnswer[13] = (responseIP & 0x00ff0000) >> 16;
        QAnswer[14] = (responseIP & 0x0000ff00) >>  8;
        QAnswer[15] = (responseIP & 0x000000ff);

        QAnswer[6] = (ttl & 0xff000000) >> 24;
        QAnswer[7] = (ttl & 0x00ff0000) >> 16;
        QAnswer[8] = (ttl & 0x0000ff00) >>  8;
        QAnswer[9] = (ttl & 0x000000ff);

        // We add our answer containing our ip of choice! (localhost/127.0.0.1/injected server ip by default, change it in setings or adding a host with a custom ip to either list)
        if(spliceOffset < (quint32)dnsrequest.size()) //Make sure the splice offset / where the answer(s) should go is in bounds or don't use it
            dnsrequest.insert(spliceOffset, (char*)QAnswer, 16);
        else
            dnsrequest.append((char*)QAnswer, 16);
    }
}

void morphRequestIntoARecordResponse(QByteArray &dnsrequest, std::vector<quint32> &responseIPs, quint32 spliceOffset, quint32 ttl)
{
    if(dnsrequest.size() >= DNS_HEADER_SIZE) //Make sure there's at least a dns header here to write to
    {
        DNS_HEADER *header = (DNS_HEADER*)dnsrequest.data();

        header->QUERY_RESPONSE_FLAG = 1; //Change from query to response
        if(header->rd == 1) //Do this so there's not even a warning about about recursion requested but not available, let's say yes if it's requested.
            header->RECURSION_AVAILABLE_FLAG = 1;
        header->rcode = RCODE_NOERROR;
        // DNS Answer
        unsigned char QAnswer[] = {
            0xc0,0x0c, // 1100 0000 0000 1100 -> offset = 12
            0x00,0x01, // Type  : A
            0x00,0x01, // Class : IN
            0x00,0x01,0x51,0x80, // TTL = 86400 -> 24h
            0x00,0x04, // RD Length
            0x00,0x00,0x00,0x00 // RDATA
        };

        QAnswer[6] = (ttl & 0xff000000) >> 24;
        QAnswer[7] = (ttl & 0x00ff0000) >> 16;
        QAnswer[8] = (ttl & 0x0000ff00) >>  8;
        QAnswer[9] = (ttl & 0x000000ff);

        if(responseIPs.size() > 0)
        {
            quint16 count = 0;
            QByteArray answers;
            for(quint32 ip : responseIPs)
            {
                QAnswer[12] = (ip & 0xff000000) >> 24;
                QAnswer[13] = (ip & 0x00ff0000) >> 16;
                QAnswer[14] = (ip & 0x0000ff00) >>  8;
                QAnswer[15] = (ip & 0x000000ff);

                // We add as many answers as ips we have to return to the requester
                answers.append((char*)QAnswer, 16);
                count++;
            }
            header->ans_count = qToBigEndian(count);

            if(spliceOffset < (quint32)dnsrequest.size()) //Make sure the splice offset / where the answer(s) should go is in bounds or don't use it
                dnsrequest.insert(spliceOffset, answers);
            else
                dnsrequest.append(answers);
        }
        else
        {
            // NXDOMAIN -> Non eXistent domain
            header->ans_count = 0;
            header->rcode = RCODE_NXDOMAIN;
        }
    }
}

InitialResponse::InitialResponse(DNSInfo &dns, QObject *parent)
{
    Q_UNUSED(parent);
    respondTo.question.qtype = dns.question.qtype;
    respondTo.domainString = dns.domainString;
    respondTo.sender = dns.sender;
    respondTo.senderPort = dns.senderPort;
    respondTo.req = dns.req;
    respondTo.ttl = dns.ttl;
    timeWithoutAResponse = QDateTime::currentDateTime();
    responseHandled = false;
}

void InitialResponse::lookupDoneSendResponseNow(DNSInfo &dns, QUdpSocket *serversocket)
{
    if(respondTo == dns && !responseHandled)
    {
        if(respondTo.req.size() > DNS_HEADER_SIZE)
        {
            if(dns.question.qtype == DNS_TYPE_A)
            {
                if(dns.hasIPs)
                {
                    morphRequestIntoARecordResponse(respondTo.req, dns.ipaddresses, dns.answeroffset, respondTo.ttl);
                    serversocket->writeDatagram(respondTo.req, respondTo.sender, respondTo.senderPort);
                    qDebug() << "[A RECORD] to:" << respondTo.sender << respondTo.senderPort << "\n" << respondTo.req;
                }
            }
            else
            {
                if(dns.res.size() > DNS_HEADER_SIZE)
                {
                    *(quint16*)dns.res.data() = *(quint16*)respondTo.req.data(); //match the request/response ids in case they aren't matching
                    serversocket->writeDatagram(dns.res, respondTo.sender, respondTo.senderPort);
                    qDebug() << "Responding to a type:" << dns.question.qtype << "\n" << dns.res;
                }
            }
        }

        qDebug() << "Response handled in:" << ((float)timeWithoutAResponse.msecsTo(QDateTime::currentDateTime()) / 1000.0f) << "secs";
        responseHandled = true;
        this->deleteLater();
    }
}

void InitialResponse::deleteObjectsTheresNoResponseFor()
{
    if(!responseHandled && timeWithoutAResponse.secsTo(QDateTime::currentDateTime()) > 60)
        this->deleteLater();
}
