#ifndef MESSAGESTHREAD_H
#define MESSAGESTHREAD_H

#include <QThread>
#include <QProcess>
#include "smalldnsserver.h"
#include "smallhttpserver.h"

class AppData
{
public:
    static AppData* instance;
    SmallDNSServer *dnsServer;
    SmallHTTPServer *httpServer;

    AppData();
    static AppData* get();
};

class MessagesThread : public QThread
{
    Q_OBJECT
public:
    AppData *data;
    void run();

signals:
    void serversInitialized();
};

#endif // MESSAGESTHREAD_H
