#include "indexhtml.h"
#include "ui_indexhtml.h"

IndexHTML::IndexHTML(QWidget *parent) : QMainWindow(parent),ui(new Ui::IndexHTML)
{
    ui->setupUi(this);
}

IndexHTML::~IndexHTML()
{
    delete ui;
}

void IndexHTML::setHTML(QString &html)
{
   ui->html->clear();
   ui->html->appendPlainText(html);
}

QString IndexHTML::getHTML()
{
    return ui->html->toPlainText();
}
void IndexHTML::on_okButton_clicked()
{
    QString html = ui->html->toPlainText();
    emit htmlChanged(html);
    hide();
}
