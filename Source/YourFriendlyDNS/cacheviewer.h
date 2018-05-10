#ifndef CACHEVIEWER_H
#define CACHEVIEWER_H

#include <QMainWindow>
#include "dnsinfo.h"

namespace Ui {
class CacheViewer;
}

class CacheViewer : public QMainWindow
{
    Q_OBJECT

public:
    explicit CacheViewer(QWidget *parent = 0);
    ~CacheViewer();

signals:
    void deleteEntriesFromCache(std::vector<ListEntry> entries);

public slots:
    void displayCache(const std::vector<DNSInfo> &cache);

private slots:
    void on_okButton_clicked();
    void on_removeButton_clicked();

private:
    Ui::CacheViewer *ui;
};

#endif // CACHEVIEWER_H
