#include "dnsserverwindow.h"
#include "ui_dnsserverwindow.h"

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

DNSServerWindow::DNSServerWindow(QWidget *parent) : QMainWindow(parent), ui(new Ui::DNSServerWindow)
{
    ui->setupUi(this);
    settings = new SettingsWindow(this);
    connect(settings, SIGNAL(settingsUpdated()), this, SLOT(settingsUpdated()));
    server = new SmallDNSServer();
    connect(server, SIGNAL(queryRespondedTo(ListEntry)), this, SLOT(queryRespondedTo(ListEntry)));
    connect(settings, SIGNAL(clearDNSCache()), server, SLOT(clearDNSCache()));
    if(server->startServer())
        qDebug() << "DNS server started on address:" << server->serversock.localAddress() << "and port:" << server->serversock.localPort();

    settingspath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir d{settingspath};
    if(d.mkpath(d.absolutePath()))
        qDebug() << "YourFriendlyDNS settings storage location:" << settingspath;

    settingspath += QDir::separator();
    settingspath += "YourFriendlyDNS.settings";
    qDebug() << "YourFriendlyDNS settings file path:" << settingspath;
    settingsLoad();
    settingsUpdated();

    QString listeningips = "Listening IPs: ";
    QList<QHostAddress> list = QNetworkInterface::allAddresses();
    for(int nIter=0; nIter<list.count(); nIter++)
    {
        if(!list[nIter].isLoopback())
        {
            if(list[nIter].protocol() == QAbstractSocket::IPv4Protocol)
            {
                listeningips += list[nIter].toString();
                if((nIter + 2) != (list.count() - 1))
                    listeningips += ", ";
            }
        }
    }
    ui->listeningIPs->setText(listeningips);
}

DNSServerWindow::~DNSServerWindow()
{
    settingsSave();
    delete server;
    delete settings;
    delete ui;
}

void DNSServerWindow::settingsUpdated()
{
    server->blockmode_returnlocalhost = settings->blockmode_localhost;
    server->ipToRespondWith = QHostAddress(settings->getRespondingIP()).toIPv4Address();
    server->cachedMinutesValid = settings->getCachedMinutesValid();
    server->realdns = settings->returnRealDNSServers();
}

void DNSServerWindow::queryRespondedTo(ListEntry e)
{
    QString ip = e.ip ? QHostAddress(e.ip).toString() : "";

    for(int i = 0; i < ui->dnsqueries->topLevelItemCount(); i++)
    {
        if(ui->dnsqueries->topLevelItem(i)->text(1) == e.hostname)
        {
            //if(e.ip != 0)
                ui->dnsqueries->topLevelItem(i)->setText(0, ip);
            return;
        }
    }

    ui->dnsqueries->addTopLevelItem(new QTreeWidgetItem(QStringList() << ip << e.hostname));
}

void DNSServerWindow::on_firstAddButton_clicked()
{
    bool append = true;
    ListEntry e(ui->hostnameEdit->text());
    if(!ui->ipEdit->text().isEmpty())
        e.ip = QHostAddress(ui->ipEdit->text()).toIPv4Address();

    ui->hostnameEdit->clear();
    ui->ipEdit->clear();
    if(server->whitelistmode)
    {
        for(ListEntry &entry : server->whitelist)
        {
            if(entry.hostname == e.hostname)
            {
                entry.ip = e.ip;
                append = false;
            }
        }
        if(append)
            server->whitelist.append(e);
    }
    else
    {
        for(ListEntry &entry : server->blacklist)
        {
            if(entry.hostname == e.hostname)
            {
                entry.ip = e.ip;
                append = false;
            }
        }
        if(append)
            server->blacklist.append(e);
    }

    if(append)
        ui->dnslist->addTopLevelItem(new QTreeWidgetItem(QStringList() << ui->ipEdit->text() << ui->hostnameEdit->text()));
}

void DNSServerWindow::refreshList()
{
    ui->dnslist->clear();
    ui->dnslist->clear();
    if(server->whitelistmode)
    {
        for(ListEntry &e : server->whitelist)
        {
            if(e.ip == 0)
                ui->dnslist->addTopLevelItem(new QTreeWidgetItem(QStringList() << "" << e.hostname));
            else
                ui->dnslist->addTopLevelItem(new QTreeWidgetItem(QStringList() << QHostAddress(e.ip).toString() << e.hostname));
        }
    }
    else
    {
        for(ListEntry &e : server->blacklist)
        {
            if(e.ip == 0)
                ui->dnslist->addTopLevelItem(new QTreeWidgetItem(QStringList() << "" << e.hostname));
            else
                ui->dnslist->addTopLevelItem(new QTreeWidgetItem(QStringList() << QHostAddress(e.ip).toString() << e.hostname));
        }
    }
}

void DNSServerWindow::on_whitelistButton_clicked()
{
    server->whitelistmode = true;
    ui->secondAddButton->setText("^ Add to whitelist ^");
    ui->whitelistButton->setChecked(true);
    refreshList();
}

void DNSServerWindow::on_blacklistButton_clicked()
{
    server->whitelistmode = false;
    ui->secondAddButton->setText("^ Add to blacklist ^");
    ui->blacklistButton->setChecked(true);
    refreshList();
}

void DNSServerWindow::on_pushButton_clicked()
{
    settings->show();
}

bool DNSServerWindow::settingsSave()
{
    QFile file(settingspath);
    if(file.open(QFile::WriteOnly))
    {
        QJsonObject json;
        json["initialMode"] = server->initialMode;
        json["whitelistmode"] = server->whitelistmode;
        json["blockmode_returnlocalhost"] = server->blockmode_returnlocalhost;
        json["ipToRespondWith"] = (int)server->ipToRespondWith;
        json["cachedMinutesValid"] = (int)server->cachedMinutesValid;

        QJsonArray dnsarray;
        foreach(const QString dns, server->realdns)
        {
            dnsarray.append(dns);
        }
        json["real_dns_servers"] = dnsarray;

        QJsonArray whitelistarray;
        foreach(const ListEntry w, server->whitelist)
        {
            QJsonObject subObject;
            subObject["hostname"] = w.hostname;
            subObject["ip"] = (int)w.ip;
            whitelistarray.append(subObject);
        }
        json["whitelist"] = whitelistarray;

        QJsonArray blacklistarray;
        foreach(const ListEntry b, server->blacklist)
        {
            QJsonObject subObject;
            subObject["hostname"] = b.hostname;
            subObject["ip"] = (int)b.ip;
            blacklistarray.append(subObject);
        }
        json["blacklist"] = blacklistarray;

        QJsonDocument jsondoc(json);
        file.write(jsondoc.toJson());
        file.close();
        return true;
    }

    return false;
}

bool DNSServerWindow::settingsLoad()
{
    QFile file(settingspath);
    if(!file.open(QFile::ReadOnly))
    {
        settingsSave();
        return false;
    }

    QJsonDocument jsondoc(QJsonDocument::fromJson(file.readAll()));
    QJsonObject json = jsondoc.object();

    if(json.contains("initialMode") && json["initialMode"].isBool())
    {
        server->initialMode = json["initialMode"].toBool();
        ui->initialMode->setChecked(server->initialMode);
    }
    if(json.contains("blockmode_returnlocalhost") && json["blockmode_returnlocalhost"].isBool())
    {
        server->blockmode_returnlocalhost = json["blockmode_returnlocalhost"].toBool();
        settings->blockmode_localhost = server->blockmode_returnlocalhost;
        if(!settings->blockmode_localhost)
            settings->setBlockOptionNoResponse();
    }
    if(json.contains("ipToRespondWith") && json["ipToRespondWith"].isDouble())
    {
        server->ipToRespondWith = json["ipToRespondWith"].toInt();
        settings->setRespondingIP(QHostAddress(server->ipToRespondWith).toString());
    }
    if(json.contains("cachedMinutesValid") && json["cachedMinutesValid"].isDouble())
    {
        server->cachedMinutesValid = json["cachedMinutesValid"].toInt();
        settings->setCachedMinutesValid(server->cachedMinutesValid);
    }

    if(json.contains("real_dns_servers") && json["real_dns_servers"].isArray())
    {
        QJsonArray serversarray=json["real_dns_servers"].toArray();
        settings->clearDNSServers();
        server->realdns.clear();
        server->realdns.reserve(serversarray.size());
        for(int i=0; i<serversarray.size(); ++i)
        {
            QString dns=serversarray[i].toString();
            qDebug() << "dns server loaded:" << dns;
            server->realdns.push_back(dns);
            settings->appendDNSServer(dns);
        }
    }

    if(json.contains("whitelist") && json["whitelist"].isArray())
    {
        QJsonArray whitelistarray=json["whitelist"].toArray();
        server->whitelist.clear();
        server->whitelist.reserve(whitelistarray.size());
        for(int i=0; i<whitelistarray.size(); ++i)
        {
            ListEntry e;
            QJsonObject entry=whitelistarray[i].toObject();
            if(entry.contains("hostname") && entry["hostname"].isString())
                e.hostname = entry["hostname"].toString();
            if(entry.contains("ip") && entry["ip"].isDouble())
                e.ip = entry["ip"].toInt();

            qDebug() << "whitelist entry loaded:" << e.hostname << QHostAddress(e.ip);
            server->whitelist.push_back(e);
        }
    }

    if(json.contains("blacklist") && json["blacklist"].isArray())
    {
        QJsonArray blacklistarray=json["blacklist"].toArray();
        server->blacklist.clear();
        server->blacklist.reserve(blacklistarray.size());
        for(int i=0; i<blacklistarray.size(); ++i)
        {
            ListEntry e;
            QJsonObject entry=blacklistarray[i].toObject();
            if(entry.contains("hostname") && entry["hostname"].isString())
                e.hostname = entry["hostname"].toString();
            if(entry.contains("ip") && entry["ip"].isDouble())
                e.ip = entry["ip"].toInt();

            qDebug() << "blacklist entry loaded:" << e.hostname << QHostAddress(e.ip);
            server->blacklist.push_back(e);
        }
    }

    if(json.contains("whitelistmode") && json["whitelistmode"].isBool())
    {
        server->whitelistmode = json["whitelistmode"].toBool();
        if(!server->whitelistmode)
            on_blacklistButton_clicked();
    }

    refreshList();

    file.close();
    return true;
}

void DNSServerWindow::on_initialMode_stateChanged(int arg1)
{
    if(arg1)
        server->initialMode = true;
    else
        server->initialMode = false;

    qDebug() << "initial mode:" << server->initialMode;
}

void DNSServerWindow::on_pushButton_2_clicked()
{
    settingsSave();
}

void DNSServerWindow::on_removeButton_clicked()
{
    auto selected = ui->dnslist->selectedItems();
    for(QTreeWidgetItem *i : selected)
    {
        if(server->whitelistmode)
        {
            for(int x = 0; x < server->whitelist.size(); x++)
            {
                if(i->text(1) == server->whitelist[x].hostname)
                {
                    qDebug() << "Removing from whitelist:" << i->text(1);
                    server->whitelist.remove(x);
                    break;
                }
            }
        }
        else
        {
            for(int x = 0; x < server->blacklist.size(); x++)
            {
                if(i->text(1) == server->blacklist[x].hostname)
                {
                     qDebug() << "Removing from blacklist:" << i->text(1);
                    server->blacklist.remove(x);
                    break;
                }
            }
        }
    }
    qDeleteAll(selected);
}

void DNSServerWindow::on_hostnameEdit_returnPressed()
{
    on_firstAddButton_clicked();
}

void DNSServerWindow::on_ipEdit_returnPressed()
{
    on_firstAddButton_clicked();
}

void DNSServerWindow::on_secondAddButton_clicked()
{
    bool alreadyAdded = false;
    if(server->whitelistmode)
    {
        for(QTreeWidgetItem *i : ui->dnsqueries->selectedItems())
        {
            for(ListEntry &e : server->whitelist)
            {
                if(e.hostname == i->text(1))
                {
                    alreadyAdded = true;
                    break;
                }
            }

            if(!alreadyAdded)
                server->whitelist.append(ListEntry(i->text(1)));
        }
    }
    else
    {
        for(QTreeWidgetItem *i : ui->dnsqueries->selectedItems())
        {
            for(ListEntry &e : server->blacklist)
            {
                if(e.hostname == i->text(1))
                {
                    alreadyAdded = true;
                    break;
                }
            }

            if(!alreadyAdded)
                server->blacklist.append(ListEntry(i->text(1)));
        }
    }
    refreshList();
}
