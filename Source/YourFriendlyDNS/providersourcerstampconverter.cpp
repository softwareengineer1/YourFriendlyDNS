#include "providersourcerstampconverter.h"
#include "ui_providersourcerstampconverter.h"

providerSourcerStampConverter::providerSourcerStampConverter(QWidget *parent) : QMainWindow(parent), ui(new Ui::providerSourcerStampConverter)
{
    ui->setupUi(this);
    decodingStampRightNow = false;
    hideUnrelated(1);

    connect(ui->ipportEdit, &QLineEdit::editingFinished, this, &providerSourcerStampConverter::encodeStamp);
    connect(ui->doesntLog, &QCheckBox::clicked, this, &providerSourcerStampConverter::encodeStamp);
    connect(ui->doesntFilter, &QCheckBox::clicked, this, &providerSourcerStampConverter::encodeStamp);
    connect(ui->supportsDNSSEC, &QCheckBox::clicked, this, &providerSourcerStampConverter::encodeStamp);
    connect(ui->pubkeyEdit, &QLineEdit::editingFinished, this, &providerSourcerStampConverter::encodeStamp);
    connect(ui->nameEdit, &QLineEdit::editingFinished, this, &providerSourcerStampConverter::encodeStamp);
    connect(ui->hashesEdit, &QLineEdit::editingFinished, this, &providerSourcerStampConverter::encodeStamp);
    connect(ui->pathEdit, &QLineEdit::editingFinished, this, &providerSourcerStampConverter::encodeStamp);
}

providerSourcerStampConverter::~providerSourcerStampConverter()
{
    delete ui;
}

bool providerSourcerStampConverter::addSource(QString sourceURL, bool forceUpdate)
{
    for(ProviderSource &src : providerSources)
    {
        if(src.url == sourceURL)
        {
            ui->sourcesBox->setCurrentText(sourceURL);
            connect(&src, &ProviderSource::displayProviders, this, &providerSourcerStampConverter::displayProviders);
            if(forceUpdate)
                src.downloadAndUpdate();
            else
                src.downloadAndUpdateIfNeeded();

            return false;
        }
    }

    ui->sourcesBox->addItem(sourceURL);
    ui->sourcesBox->setCurrentText(sourceURL);
    return true;
}

void providerSourcerStampConverter::clearSources()
{
    providerSources.clear();
}

void providerSourcerStampConverter::loadSource(QString sourceURL, bool forceUpdate, QByteArray hash, QDateTime lastUpdated)
{
    if(addSource(sourceURL, forceUpdate))
    {
        ProviderSource src(sourceURL, hash, lastUpdated);

        if(forceUpdate)
            src.downloadAndUpdate();
        else
            src.downloadAndUpdateIfNeeded();
        providerSources.append(src);
        connect(&providerSources.back(), &ProviderSource::displayProviders, this, &providerSourcerStampConverter::displayProviders);
    }
}

void providerSourcerStampConverter::decodeStamp(QString sdns)
{
    if(sdns.size() > 0)
    {
        ui->stampEdit->setText(sdns);
        emit ui->stampEdit->editingFinished();
    }
}

void providerSourcerStampConverter::clearStampFields()
{
    ui->pubkeyEdit->setText("");
    ui->nameEdit->setText("");
    ui->hashesEdit->setText("");
    ui->hostnameEdit->setText("");
    ui->pathEdit->setText("");
}

void providerSourcerStampConverter::encodeStamp()
{
    if(!decodingStampRightNow)
    {
        DNSCryptProvider provider;
        provider.protocolVersion = ui->protocolVersionBox->currentIndex();
        provider.addr = ui->ipportEdit->text();
        provider.props = 0;
        if(ui->doesntLog->isChecked()) provider.props |= 2;
        if(ui->doesntFilter->isChecked()) provider.props |= 4;
        if(ui->supportsDNSSEC->isChecked()) provider.props |= 1;

        if(provider.protocolVersion == 1)
        {
            provider.providerPubKey = QByteArray::fromHex(ui->pubkeyEdit->text().toUtf8());
            provider.providerName = ui->nameEdit->text();
        }
        else if(provider.protocolVersion == 2 || provider.protocolVersion == 3)
        {
            QStringList hashes = ui->hashesEdit->text().split(",", QString::SkipEmptyParts);
            for(QString &hash : hashes)
            {
                provider.hashes.append(QByteArray::fromHex(hash.toUtf8()));
            }
            provider.origHost = ui->hostnameEdit->text();

            if(provider.protocolVersion == 2)
                provider.path = ui->pathEdit->text();
        }

        ui->stampEdit->setText(provider.toStamp());
    }
}

void providerSourcerStampConverter::on_stampEdit_editingFinished()
{
    if(ui->stampEdit->text().size() > 0)
    {
        decodingStampRightNow = true;

        DNSCryptProvider provider(ui->stampEdit->text().toUtf8());
        if(provider.protocolVersion <= ui->protocolVersionBox->count())
            ui->protocolVersionBox->setCurrentIndex(provider.protocolVersion);

        ui->doesntLog->setChecked(provider.props & 2);
        ui->doesntFilter->setChecked(provider.props & 4);
        ui->supportsDNSSEC->setChecked(provider.props & 1);

        ui->ipportEdit->setText(provider.origAddr);
        clearStampFields();

        if(provider.protocolVersion == 1)
        {
            ui->pubkeyEdit->setText(provider.providerPubKey.toHex());
            ui->nameEdit->setText(provider.providerName);
        }
        else if(provider.protocolVersion == 2 || provider.protocolVersion == 3)
        {
            QString hashesString;
            if(provider.hashes.size() > 0)
            {
                for(QByteArray &i : provider.hashes)
                {
                    hashesString += i.toHex() + ", ";
                }
                hashesString.truncate(hashesString.size() - 2);
            }
            ui->hashesEdit->setText(hashesString);

            ui->hostnameEdit->setText(provider.origHost);

            if(provider.protocolVersion == 2)
                ui->pathEdit->setText(provider.path);
        }

        decodingStampRightNow = false;
    }
}

void providerSourcerStampConverter::on_protocolVersionBox_currentIndexChanged(int index)
{
    hideUnrelated(index);
    encodeStamp();
}

void providerSourcerStampConverter::on_addSourceButton_clicked()
{
    loadSource(ui->sourceEdit->text(), true);
    emit on_updateSourceButton_clicked();
}

void providerSourcerStampConverter::on_updateSourceButton_clicked()
{
    loadSource(ui->sourcesBox->currentText(), true);
}

void providerSourcerStampConverter::displayProviders(QVector<ProviderFromSource> &displayProviders)
{
    ui->autosourcesTree->clear();
    for(ProviderFromSource &p : displayProviders)
    {
        QTreeWidgetItem *i = new QTreeWidgetItem(QStringList() << p.name.toStdString().c_str() << p.stamp.toStdString().c_str());
        if(i)
        {
            i->addChild(new QTreeWidgetItem(QStringList() << p.description));
            ui->autosourcesTree->addTopLevelItem(i);
        }
    }
}

void providerSourcerStampConverter::on_sourcesBox_activated(const QString &arg1)
{
    for(ProviderSource &src : providerSources)
    {
        if(src.url == arg1)
            return loadSource(src.url);
    }
}

void providerSourcerStampConverter::on_autosourcesTree_currentItemChanged(QTreeWidgetItem *current, QTreeWidgetItem *previous)
{
    Q_UNUSED(previous);
    if(current)
    {
        if(current->columnCount() > 1)
            decodeStamp(current->text(1));
    }
}

void providerSourcerStampConverter::on_addItButton_clicked()
{
    emit addToServerList(ui->stampEdit->text());
}

void providerSourcerStampConverter::hideUnrelated(quint8 version)
{
    if(version == 0)
    {
        ui->pubkeyLabel->setVisible(false);
        ui->pubkeyEdit->setVisible(false);
        ui->nameLabel->setVisible(false);
        ui->nameEdit->setVisible(false);
        ui->hashesLabel->setVisible(false);
        ui->hashesEdit->setVisible(false);
        ui->hostnameLabel->setVisible(false);
        ui->hostnameEdit->setVisible(false);
        ui->pathLabel->setVisible(false);
        ui->pathEdit->setVisible(false);
    }
    else if(version == 1)
    {
        ui->pubkeyLabel->setVisible(true);
        ui->pubkeyEdit->setVisible(true);
        ui->nameEdit->setVisible(true);
        ui->nameLabel->setVisible(true);
        ui->hashesLabel->setVisible(false);
        ui->hashesEdit->setVisible(false);
        ui->hostnameLabel->setVisible(false);
        ui->hostnameEdit->setVisible(false);
        ui->pathLabel->setVisible(false);
        ui->pathEdit->setVisible(false);
    }
    else if(version == 2 || version == 3)
    {
        ui->pubkeyLabel->setVisible(false);
        ui->pubkeyEdit->setVisible(false);
        ui->nameLabel->setVisible(false);
        ui->nameEdit->setVisible(false);
        ui->hashesLabel->setVisible(true);
        ui->hashesEdit->setVisible(true);
        ui->hostnameLabel->setVisible(true);
        ui->hostnameEdit->setVisible(true);
        if(version == 2)
        {
            ui->pathLabel->setVisible(true);
            ui->pathEdit->setVisible(true);
        }
        else
        {
            ui->pathLabel->setVisible(false);
            ui->pathEdit->setVisible(false);
        }
    }
}
