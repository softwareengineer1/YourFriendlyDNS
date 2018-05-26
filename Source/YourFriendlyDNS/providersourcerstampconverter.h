#ifndef PROVIDERSOURCERSTAMPCONVERTER_H
#define PROVIDERSOURCERSTAMPCONVERTER_H

#include <QMainWindow>
#include <QTreeWidget>
#include "dnscrypt.h"

namespace Ui {
class providerSourcerStampConverter;
}

class providerSourcerStampConverter : public QMainWindow
{
    Q_OBJECT

public:
    explicit providerSourcerStampConverter(QWidget *parent = 0);
    ~providerSourcerStampConverter();
    bool addSource(QString sourceURL, bool forceUpdate = false);
    void clearStampFields();
    void hideUnrelated(quint8 version);
    QVector<ProviderSource> providerSources;

private:
    bool decodingStampRightNow;

public slots:
    void clearSources();
    void loadSource(QString sourceURL, bool forceUpdate = false, QByteArray hash = "", QDateTime lastUpdated = QDateTime());
    void decodeStamp(QString sdns);
    void displayProviders(QVector<ProviderFromSource> &displayProviders);

private slots:
    void encodeStamp();
    void on_stampEdit_editingFinished();
    void on_protocolVersionBox_currentIndexChanged(int index);
    void on_addSourceButton_clicked();
    void on_updateSourceButton_clicked();
    void on_sourcesBox_activated(const QString &arg1);
    void on_autosourcesTree_currentItemChanged(QTreeWidgetItem *current, QTreeWidgetItem *previous);
    void on_addItButton_clicked();

signals:
    void addToServerList(QString stamp);

private:
    Ui::providerSourcerStampConverter *ui;
};

#endif // PROVIDERSOURCERSTAMPCONVERTER_H
