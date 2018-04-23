#include "initialresponse.h"

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

void morphRequestIntoARecordResponse(QByteArray &dnsrequest, quint32 responseIP, quint32 spliceOffset)
{
    if(dnsrequest.size() >= DNS_HEADER_SIZE) //Make sure there's at least a dns header here to write to
    {
        char *ptr = dnsrequest.data();

        ptr[DNS_HEADER_FLAGS_OFFSET] |= AUTHORITATIVE_ANSWER_FLAG; //Make It An Answer Response
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

        // We add our answer containing our ip of choice! (localhost/127.0.0.1 by default, change it in setings or adding a host with a custom ip to either list)
        ptr[DNS_HEADER_ANSWER_COUNT_OFFSET]++;

        if(spliceOffset <= (quint32)dnsrequest.size()) //Make sure the splice offset / where the answer(s) should go is in bounds or don't use it
            dnsrequest.insert(spliceOffset, (char*)QAnswer, 16);
        else
            dnsrequest.append((char*)QAnswer, 16);
    }
}

void morphRequestIntoARecordResponse(QByteArray &dnsrequest, std::vector<quint32> &responseIPs, quint32 spliceOffset)
{
    if(dnsrequest.size() >= DNS_HEADER_SIZE) //Make sure there's at least a dns header here to write to
    {
        char *ptr = dnsrequest.data();

        //qDebug() << "request before morph:\n" << dnsrequest.toHex();

        ptr[DNS_HEADER_FLAGS_OFFSET] |= AUTHORITATIVE_ANSWER_FLAG; //Make It An Answer Response
        // DNS Answer
        unsigned char QAnswer[] = {
            0xc0,0x0c, // 1100 0000 0000 1100 -> offset = 12
            0x00,0x01, // Type  : A
            0x00,0x01, // Class : IN
            0x00,0x01,0x51,0x80, // TTL = 86400 -> 24h
            0x00,0x04, // RD Length
            0x00,0x00,0x00,0x00 // RDATA
        };

        if(!responseIPs.empty())
        {
            QByteArray answers;
            for(quint32 ip : responseIPs)
            {
                QAnswer[12] = (ip & 0xff000000) >> 24;
                QAnswer[13] = (ip & 0x00ff0000) >> 16;
                QAnswer[14] = (ip & 0x0000ff00) >>  8;
                QAnswer[15] = (ip & 0x000000ff);

                // We add as many answers as ips we have to return to the requester
                ptr[DNS_HEADER_ANSWER_COUNT_OFFSET]++;
                answers.append((char*)QAnswer, 16);
            }

            if(spliceOffset <= (quint32)dnsrequest.size()) //Make sure the splice offset / where the answer(s) should go is in bounds or don't use it
                dnsrequest.insert(spliceOffset, answers);
            else
                dnsrequest.append(answers);
            //qDebug() << "Morphed into response:\n" << dnsrequest.toHex();
        }
        else
        {
            // EDNS not supported
            ptr[DNS_HEADER_FLAGS_OFFSET+1] &= 0xf0;
            ptr[DNS_HEADER_FLAGS_OFFSET+1] |= 4; // NOTIMPL
        }
    }
}

InitialResponse::InitialResponse(DNSInfo &dns, QObject *parent)
{
    Q_UNUSED(parent);
    whoWeNeedToRespondImmediatelyTo.domainString = dns.domainString;
    whoWeNeedToRespondImmediatelyTo.sender = dns.sender;
    whoWeNeedToRespondImmediatelyTo.senderPort = dns.senderPort;
    whoWeNeedToRespondImmediatelyTo.req = dns.req;
    responseHandled = false;
}

void InitialResponse::lookupDoneSendResponseNow(DNSInfo &dns, QUdpSocket *serversocket)
{
    if(whoWeNeedToRespondImmediatelyTo.domainString == dns.domainString && !responseHandled)
    {
        qDebug() << "For initial response, matched:" << whoWeNeedToRespondImmediatelyTo.domainString << "with:" << dns.domainString;
        if(dns.question.qtype == DNS_TYPE_A)
        {
            if(!dns.ipaddresses.empty())
            {
                qDebug() << "Morphing and responding with an A record! to:" << whoWeNeedToRespondImmediatelyTo.sender
                         << whoWeNeedToRespondImmediatelyTo.senderPort << "with ips (first one):" << QHostAddress(dns.ipaddresses[0]).toString()
                         << "request:" << whoWeNeedToRespondImmediatelyTo.req;

                morphRequestIntoARecordResponse(whoWeNeedToRespondImmediatelyTo.req, dns.ipaddresses, dns.answeroffset);

                qDebug() << "response:" << whoWeNeedToRespondImmediatelyTo.req;

                serversocket->writeDatagram(whoWeNeedToRespondImmediatelyTo.req, whoWeNeedToRespondImmediatelyTo.sender, whoWeNeedToRespondImmediatelyTo.senderPort);
            }
        }
        else
        {
            *(quint16*)dns.res.data() = *(quint16*)whoWeNeedToRespondImmediatelyTo.req.data(); //match the request/response ids incase they aren't matching
            qDebug() << "Responding to non A record! response:\n" << dns.res;
            serversocket->writeDatagram(dns.res, whoWeNeedToRespondImmediatelyTo.sender, whoWeNeedToRespondImmediatelyTo.senderPort);
        }

        responseHandled = true;
        this->deleteLater();
    }
}