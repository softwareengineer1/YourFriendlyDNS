#ifndef DNSSERVERWINDOW_H
#define DNSSERVERWINDOW_H

#include <QMainWindow>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QFile>
#include <QDir>
#include <QStandardPaths>
#include "settingswindow.h"
#include "messagesthread.h"

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

namespace Ui {
class DNSServerWindow;
}

class DNSServerWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit DNSServerWindow(QWidget *parent = 0);
    ~DNSServerWindow();

public slots:
    void serversInitialized();
    void androidInit();
    void htmlChanged(QString &html);
    void setIPToFirstListening();

private slots:
    void settingsUpdated();
    void queryRespondedTo(ListEntry e);
    void autoCaptureCaptivePortals();
    void iptablesUndoAndroid();
    void on_firstAddButton_clicked();
    void on_whitelistButton_clicked();
    void on_blacklistButton_clicked();
    void on_initialMode_stateChanged(int arg1);
    void on_saveButton_clicked();
    void on_removeButton_clicked();
    void on_hostnameEdit_returnPressed();
    void on_ipEdit_returnPressed();
    void on_secondAddButton_clicked();
    void on_settingsButton_clicked();

private:
    Ui::DNSServerWindow *ui;
    MessagesThread *messagesThread;
    SettingsWindow *settings;
    SmallDNSServer *server;
    SmallHTTPServer *httpServer;
    QString settingspath, html, version;

    void listeningIPsUpdate();
    void appendToBlacklist(ListEntry e);
    void refreshList();
    bool settingsSave();
    bool settingsLoad();
};

#endif // DNSSERVERWINDOW_H
