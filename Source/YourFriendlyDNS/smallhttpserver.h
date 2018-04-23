#ifndef SMALLHTTPSERVER_H
#define SMALLHTTPSERVER_H

#include <QTcpServer>
#include <QTcpSocket>
#include <QDateTime>
#include <QThread>

class SmallHTTPServer : public QTcpServer
{
    Q_OBJECT
public:
    explicit SmallHTTPServer(QObject *parent = nullptr);
    bool startServer(QHostAddress address = QHostAddress::AnyIPv4, quint16 port = 80);
    void setHTML(QString html);

private:
    QString html, response_header, contentType, encodingType, acceptRanges, connection;

private slots:
    void returnIndexPage();
};

#endif // SMALLHTTPSERVER_H
