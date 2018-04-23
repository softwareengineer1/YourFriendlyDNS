#ifndef INDEXHTML_H
#define INDEXHTML_H

#include <QMainWindow>

namespace Ui {
class IndexHTML;
}

class IndexHTML : public QMainWindow
{
    Q_OBJECT

public:
    explicit IndexHTML(QWidget *parent = 0);
    ~IndexHTML();
    void setHTML(QString &html);
    QString getHTML();

signals:
    void htmlChanged(QString &html);

private slots:
    void on_okButton_clicked();

private:
    Ui::IndexHTML *ui;
};

#endif // INDEXHTML_H
