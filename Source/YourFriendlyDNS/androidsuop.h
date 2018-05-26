#ifndef ANDROIDSUOP_H
#define ANDROIDSUOP_H

#ifdef Q_OS_ANDROID

#include <QThread>
#include <QProcess>

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

class AndroidSU_ServerOP : public QThread
{
public:
    enum class opcode
    {
        iptablesSet, iptablesRemove
    };

    opcode op;
    quint16 dnsServerPort,httpServerPort;
    AndroidSU_ServerOP(opcode op, quint16 dnsServerPort, quint16 httpServerPort = 0)
    {
        this->op = op;
        this->dnsServerPort = dnsServerPort;
        this->httpServerPort = httpServerPort;
    }
    void run()
    {
        QProcess su;
        QProcess du;
        if(op == opcode::iptablesSet)
        {
            //Run su, enable ipv4 forwarding, and do iptables redirect from port 53(dns) to 5333 (where this server is binded on android by default), also 80 to 8080 now
            du.start("su"); //First time running it, accept the root prompt
            if(!du.waitForStarted())
                return;
            du.write(QString("iptables -t nat --list | grep \"ports %1\"\n").arg(dnsServerPort).toUtf8());
            du.waitForFinished();
            QByteArray listresult = du.read(4096);
            qDebug() << "iptables dns port list result:" << listresult << "list size:" << listresult.size();

            su.start("su");
            if(!su.waitForStarted())
                return;

            if(listresult.size() == 0)
            {
                qDebug() << "iptables dns not set yet, setting dns iptables now...";
                su.write("sysctl -w net.ipv4.ip_forward=1\n");
                su.write(QString("iptables -A INPUT -p udp --dport %1 -j ACCEPT\n").arg(dnsServerPort).toUtf8());
                su.write(QString("iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports %1\n").arg(dnsServerPort).toUtf8());
            }

            if(httpServerPort != 0)
            {
                du.write(QString("iptables -t nat --list | grep \"ports %1\"\n").arg(httpServerPort).toUtf8());
                du.closeWriteChannel();
                du.waitForFinished();
                QByteArray listresult = du.read(4096);

                qDebug() << "iptables http port list result:" << listresult << "list size:" << listresult.size();
                if(listresult.size() == 0)
                {
                    qDebug() << "iptables http not set yet, setting http iptables now...";
                    su.write(QString("iptables -A INPUT -p tcp --dport %1 -j ACCEPT\n").arg(httpServerPort).toUtf8());
                    su.write(QString("iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports %1\n").arg(httpServerPort).toUtf8());
                }
            }

            su.closeWriteChannel();
            if(!su.waitForFinished())
                return;
        }
        else if(op == opcode::iptablesRemove)
        {
            su.start("su");
            if(!su.waitForStarted())
                return;

            su.write(QString("iptables -D INPUT -p udp --dport %1 -j ACCEPT\n").arg(dnsServerPort).toUtf8());
            su.write(QString("iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports %1\n").arg(dnsServerPort).toUtf8());
            if(httpServerPort != 0)
            {
                su.write(QString("iptables -D INPUT -p tcp --dport %1 -j ACCEPT\n").arg(httpServerPort).toUtf8());
                su.write(QString("iptables -t nat -D PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports %1\n").arg(httpServerPort).toUtf8());
            }
            su.closeWriteChannel();

            if(!su.waitForFinished())
                return;
        }
    }
};

#endif

#endif // ANDROIDSUOP_H
