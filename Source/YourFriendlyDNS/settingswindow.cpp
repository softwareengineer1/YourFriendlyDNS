#include "settingswindow.h"
#include "ui_settingswindow.h"

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

SettingsWindow::SettingsWindow(QWidget *parent) : QMainWindow(parent), ui(new Ui::SettingsWindow)
{
    ui->setupUi(this);
    indexhtml = new IndexHTML();
    sourcerAndStampConverter = new providerSourcerStampConverter();
    if(sourcerAndStampConverter)
    {
        connect(this, &SettingsWindow::decodeStamp, sourcerAndStampConverter, &providerSourcerStampConverter::decodeStamp);
        connect(sourcerAndStampConverter, &providerSourcerStampConverter::addToServerList, this, &SettingsWindow::addToServerList);
    }
    blockmode_localhost = true;

    #ifdef Q_OS_MACOS
    QFont font = ui->label->font();
    font.setPointSize(11);
    QList<QWidget*> widgets = this->findChildren<QWidget*>();
    foreach (QWidget *widget, widgets)
    {
        widget->setFont(font);
    }
    #endif
}

SettingsWindow::~SettingsWindow()
{
    if(sourcerAndStampConverter)
        delete sourcerAndStampConverter;
    if(indexhtml)
        delete indexhtml;
    delete ui;
}

QString SettingsWindow::returnDedicatedDNSCrypter()
{
    return ui->dedicatedDNSCrypt->text();
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
    if(!dns.isEmpty() && !isExisting(dns))
        ui->realdnsservers->addItem(dns);
}

void SettingsWindow::addToServerList(QString stamp)
{
    appendDNSServer(stamp);
}

void SettingsWindow::setRespondingIP(const QString &ip)
{
    ui->respondingIP->setText(ip);
}

void SettingsWindow::setRespondingIPv6(const QString &ipv6)
{
    ui->respondingIPv6->setText(ipv6);
}

bool SettingsWindow::getDNSCryptEnabled()
{
    return ui->dnscryptEnabled->isChecked();
}

bool SettingsWindow::getNewKeyPerRequestEnabled()
{
    return ui->newKeyPerRequest->isChecked();
}

QString SettingsWindow::getRespondingIP()
{
    return ui->respondingIP->text();
}

QString SettingsWindow::getDNSServerPort()
{
    return ui->dnsServerPort->text();
}

QString SettingsWindow::getHTTPServerPort()
{
    return ui->httpServerPort->text();
}

void SettingsWindow::setDNSCryptEnabled(bool yes)
{
    ui->dnscryptEnabled->setChecked(yes);
}

void SettingsWindow::setNewKeyPerRequest(bool yes)
{
    ui->newKeyPerRequest->setChecked(yes);
}

void SettingsWindow::setCachedMinutesValid(quint32 minutesValid)
{
     ui->cacheValidMinutes->setText(QString("%1").arg(minutesValid));
}

void SettingsWindow::setDNSServerPort(quint16 dnsServerPort)
{
    ui->dnsServerPort->setText(QString("%1").arg(dnsServerPort));
}

void SettingsWindow::setHTTPServerPort(quint16 httpServerPort)
{
    ui->httpServerPort->setText(QString("%1").arg(httpServerPort));
}

void SettingsWindow::setiptablesButtonEnabled(bool enabled)
{
    ui->iptablesUndo->setVisible(enabled);
    ui->iptablesUndo->setEnabled(enabled);
}

quint32 SettingsWindow::getCachedMinutesValid()
{
     return ui->cacheValidMinutes->text().toInt();
}

void SettingsWindow::setBlockOptionNoResponse()
{
    ui->option_noresponse->setChecked(true);
}

void SettingsWindow::setAutoInject(bool checked)
{
    ui->autoinjectBox->setChecked(checked);
    if(checked)
        emit setIPToFirstListening();
}

void SettingsWindow::setAutoTTL(bool autottl)
{
    autoTTL = autottl;
    if(autoTTL)
    {
        quint32 ttl = (ui->cacheValidMinutes->text().toInt() * 60);
        ui->dnsTTL->setText(QString("%1").arg(ttl));
        qDebug() << "Auto-setting DNS TTL:" << ttl;
    }
}

void SettingsWindow::setdnsTTL(quint32 dnsttl)
{
    dnsTTL = dnsttl;
    ui->dnsTTL->setText(QString("%1").arg(dnsttl));
    qDebug() << "Specified DNS TTL:" << dnsttl;
    emit settingsUpdated();
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

void SettingsWindow::on_editindexButton_clicked()
{
    if(indexhtml)
        indexhtml->show();
}

void SettingsWindow::on_ipinjectButton_clicked()
{
    emit setIPToFirstListening();
}

void SettingsWindow::on_autoinjectBox_stateChanged(int arg1)
{
    if(arg1)
    {
        emit setIPToFirstListening();
        autoinject = true;
    }
    else
        autoinject = false;

    emit settingsUpdated();
}

void SettingsWindow::on_captureCaptive_clicked()
{
    emit autoCaptureCaptivePortals();
}

void SettingsWindow::on_iptablesUndo_clicked()
{
    emit iptablesUndoAndroid();
}

void SettingsWindow::on_dnsTTL_textChanged(const QString &arg1)
{
    if(arg1.size() > 0)
    {
        dnsTTL = arg1.toInt();
        emit settingsUpdated();
    }
}

void SettingsWindow::on_sameAsCachedBox_stateChanged(int arg1)
{
    if(arg1)
    {
        autoTTL = true;
        setAutoTTL(autoTTL);
    }
    else
        autoTTL = false;

    emit settingsUpdated();
}

void SettingsWindow::on_cacheValidMinutes_textChanged(const QString &arg1)
{
    if(arg1.size() > 0)
    {
        if(autoTTL)
        {
            setAutoTTL(autoTTL);
        }
        emit settingsUpdated();
    }
}

void SettingsWindow::on_dnscryptEnabled_stateChanged(int arg1)
{
    if(arg1)
        setDNSCryptEnabled(arg1);
    emit settingsUpdated();
}

void SettingsWindow::on_newKeyPerRequest_stateChanged(int arg1)
{
    if(arg1)
        setNewKeyPerRequest(arg1);
    emit settingsUpdated();
}

void SettingsWindow::on_backButton_clicked()
{
    this->hide();
}

void SettingsWindow::on_getProvidersButton_clicked()
{
    if(sourcerAndStampConverter)
        sourcerAndStampConverter->show();
}

void SettingsWindow::on_realdnsservers_itemClicked(QListWidgetItem *item)
{
    if(sourcerAndStampConverter && item->text().startsWith("sdns://"))
        emit decodeStamp(item->text());
}
