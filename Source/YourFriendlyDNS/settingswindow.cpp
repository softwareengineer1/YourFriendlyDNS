#include "settingswindow.h"
#include "ui_settingswindow.h"

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

SettingsWindow::SettingsWindow(QWidget *parent) : QMainWindow(parent), ui(new Ui::SettingsWindow)
{
    ui->setupUi(this);
    blockmode_localhost = true;
}

SettingsWindow::~SettingsWindow()
{
    delete ui;
}

QVector<QString> SettingsWindow::returnRealDNSServers()
{
     QVector<QString> dnsservers;

     for(int i = 0; i < ui->realdnsservers->count(); i++)
         dnsservers.append(ui->realdnsservers->item(i)->text());

     return dnsservers;
}

void SettingsWindow::clearDNSServers()
{
    ui->realdnsservers->clear();
}

bool SettingsWindow::isExisting(const QString &dns)
{
    for(int i = 0; i < ui->realdnsservers->count(); i++)
        if(ui->realdnsservers->item(i)->text() == dns)
            return true;

    return false;
}

void SettingsWindow::appendDNSServer(const QString &dns)
{
    if(!isExisting(dns))
        ui->realdnsservers->addItem(dns);
}

void SettingsWindow::setRespondingIP(const QString &ip)
{
    ui->respondingIP->setText(ip);
}

QString SettingsWindow::getRespondingIP()
{
    return ui->respondingIP->text();
}

void SettingsWindow::setCachedMinutesValid(quint32 minutesValid)
{
     ui->cacheValidMinutes->setText(QString("%1").arg(minutesValid));
}

quint32 SettingsWindow::getCachedMinutesValid()
{
     return ui->cacheValidMinutes->text().toInt();
}

void SettingsWindow::setBlockOptionNoResponse()
{
    ui->option_noresponse->setChecked(true);
}

void SettingsWindow::on_addButton_clicked()
{
    if(!isExisting(ui->edit_dnsserver->text()))
    {
        ui->realdnsservers->addItem(ui->edit_dnsserver->text());
        ui->edit_dnsserver->clear();
        emit settingsUpdated();
    }
}

void SettingsWindow::on_removeButton_clicked()
{
    qDeleteAll(ui->realdnsservers->selectedItems());
    emit settingsUpdated();
}

void SettingsWindow::on_option_localhost_clicked()
{
    blockmode_localhost = true;
    emit settingsUpdated();
}

void SettingsWindow::on_option_noresponse_clicked()
{
    blockmode_localhost = false;
    emit settingsUpdated();
}

void SettingsWindow::on_cacheValidMinutes_editingFinished()
{
    emit settingsUpdated();
}

void SettingsWindow::on_respondingIP_editingFinished()
{
    emit settingsUpdated();
}

void SettingsWindow::on_edit_dnsserver_returnPressed()
{
    on_addButton_clicked();
}

void SettingsWindow::on_clearCacheButton_clicked()
{
    emit clearDNSCache();
}
