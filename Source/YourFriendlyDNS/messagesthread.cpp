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
with this program; if not, write to the Free Software Foundation, Inc*/

AppData* AppData::instance = nullptr;

AppData::AppData()
{
    dnsServer = nullptr;
    httpServer = nullptr;
}

AppData* AppData::get()
{
    if(instance == nullptr)
        instance = new AppData();
    return instance;
}

void MessagesThread::run()
{
    data = AppData::get();
    data->dnsServer = new SmallDNSServer();
    data->httpServer = new SmallHTTPServer();

    emit serversInitialized();

    #ifdef Q_OS_ANDROID
    if(data->dnsServer->dnsServerPort == 53)
        data->dnsServer->dnsServerPort = 5333;
    if(data->dnsServer->httpServerPort == 80)
        data->dnsServer->httpServerPort = 8080;

    AndroidSU_ServerOP *suOP = new AndroidSU_ServerOP(AndroidSU_ServerOP::opcode::iptablesSet, data->dnsServer->dnsServerPort, data->dnsServer->httpServerPort);
    connect(suOP, SIGNAL(finished()), suOP, SLOT(deleteLater()));
    suOP->start();
    emit androidInit();
    #endif

    if(data->dnsServer->startServer(QHostAddress::AnyIPv4, data->dnsServer->dnsServerPort))
        qDebug() << "DNS server started on address:" << data->dnsServer->serversock.localAddress() << "and port:" << data->dnsServer->serversock.localPort();
    if(data->httpServer->startServer(QHostAddress::AnyIPv4, data->dnsServer->httpServerPort))
        qDebug() << "HTTP server started on address:" << data->httpServer->serverAddress() << "and port:" << data->httpServer->serverPort();

    qDebug() << "MessagesThread started, for handling server duties!";
    exec(); //handles the signals and slots for objects owned by this thread
}

MessagesThread::~MessagesThread()
{
    data = AppData::get();
    if(data->httpServer)
        delete data->httpServer;
    if(data->dnsServer)
        delete data->dnsServer;
}
