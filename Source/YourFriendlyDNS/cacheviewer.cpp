#include "cacheviewer.h"
#include "ui_cacheviewer.h"

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

CacheViewer::CacheViewer(QWidget *parent) : QMainWindow(parent), ui(new Ui::CacheViewer)
{
    ui->setupUi(this);
}

CacheViewer::~CacheViewer()
{
    delete ui;
}

void CacheViewer::displayCache(const std::vector<DNSInfo> &cache)
{
    QString type, data;
    ui->cacheView->clear();
    for(const DNSInfo &dns : cache)
    {
        if(dns.question.qtype == DNS_TYPE_A) //IPv4 addresses
        {
            type = "A";
            data = "";
            if(dns.hasIPs && dns.ipaddresses.size() > 0)
            {
                for(const quint32 &i : dns.ipaddresses)
                {
                    data += QString("%1, ").arg(QHostAddress(i).toString());
                }
                data.truncate(data.size()-2);
            }
        }
        else if(dns.question.qtype == DNS_TYPE_AAAA) //IPv6 addresses
        {
            type = "AAAA";
            data = dns.res.toHex().toStdString().c_str();
        }
        else if(dns.question.qtype == DNS_TYPE_TXT) //TXT record
        {
            type = "TXT";
            QByteArray data2 = dns.res;
            if(data2.size() > DNS_HEADER_SIZE)
                data2.remove(0, DNS_HEADER_SIZE);
            data = data2.toStdString().c_str();
        }
        else
        {
            type = QString("%1").arg(dns.question.qtype);
            data = dns.res.toHex().toStdString().c_str();
        }

        ui->cacheView->addTopLevelItem(new QTreeWidgetItem(QStringList() << dns.domainString << type << dns.expiry.toString() << data));
    }
}

void CacheViewer::on_okButton_clicked()
{
    this->hide();
}

void CacheViewer::on_removeButton_clicked()
{
    std::vector<ListEntry> entries;
    auto selected = ui->cacheView->selectedItems();
    for(QTreeWidgetItem *i : selected)
    {
        if(i->text(1) == "A")
            entries.push_back(ListEntry(i->text(0), DNS_TYPE_A)); //Reusing the ip field as a record type field just for this
        else if(i->text(1) == "AAAA")
            entries.push_back(ListEntry(i->text(0), DNS_TYPE_AAAA));
        else if(i->text(1) == "TXT")
            entries.push_back(ListEntry(i->text(0), DNS_TYPE_TXT));
        else
            entries.push_back(ListEntry(i->text(0), i->text(1).toInt()));
    }
    qDeleteAll(selected);
    emit deleteEntriesFromCache(entries);
}
