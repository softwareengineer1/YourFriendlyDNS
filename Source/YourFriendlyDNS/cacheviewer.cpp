#include "cacheviewer.h"
#include "ui_cacheviewer.h"

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
