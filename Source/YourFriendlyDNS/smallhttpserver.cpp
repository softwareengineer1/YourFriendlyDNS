#include "smallhttpserver.h"

SmallHTTPServer::SmallHTTPServer(QObject *parent)
{
    Q_UNUSED(parent);
    html = "<html><head><title>Your Landing Page!</title><body bgcolor=\"skyblue\"><input type=\"text\" name=\"urlfield\" id=\"urlfield\" maxlength=\"200\" size=\"75\"></input><input type=\"button\" name=\"send\" id=\"send\" value=\"Go\" onclick=\"go()\"></input><h1>Your Landing Page!</h1> <a href=\"https://startpage.com/\">Start!</a><script>function go() { parent.window.location.href=document.getElementById(\"urlfield\").value; }</script></body></html>";
    response_header=R"(HTTP/1.1 200 OK
Content-Type: %1
Content-Encoding: %2
Content-Length: %3
Accept-Ranges: %4"
Date: %5
Connection: %6)";
    response_header += "\r\n\r\n";
    contentType = "text/html", encodingType = "identity", acceptRanges = "bytes", connection = "close";

    connect(this, &QTcpServer::newConnection, this, &SmallHTTPServer::returnIndexPage);
}

bool SmallHTTPServer::startServer(QHostAddress address, quint16 port)
{
    if(port == 0)
    {
        qDebug() << "HTTP server disabled in settings (set to port 0)";
        return false;
    }
    return listen(address, port);
}

void SmallHTTPServer::setHTML(QString html)
{
    this->html = html;
}

void SmallHTTPServer::returnIndexPage()
{
    QTcpSocket *socket = nextPendingConnection();
    connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);

    QString contentLength = QString("%1").arg(html.size());
    QString currentDateTime = QDateTime::currentDateTime().toString();

    QString response = response_header.arg(contentType).arg(encodingType).arg(contentLength).arg(acceptRanges).arg(currentDateTime).arg(connection);
    response += html;

    socket->write(response.toUtf8());
    qDebug() << "[" << socket->socketDescriptor() << "] Wrote index page:" << response;
    socket->disconnectFromHost();
}
