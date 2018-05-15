#ifndef ENCRYPTIONDIALOG_H
#define ENCRYPTIONDIALOG_H

#include <QDialog>
#include <memory>

namespace Ui{
class Dialog;
}

class EncryptionDialog : public QDialog
{
    Q_OBJECT
public:
    EncryptionDialog(QWidget *parent=0);
    ~EncryptionDialog();
    void set_text(const QString &text);

private:
    std::unique_ptr<Ui::Dialog> ui;

private slots:
    void encrypt_clicked();
    void decrypt_clicked();

signals:
    void encrypt(const QString &text);
    void decrypt(const QString &text);
};

#endif // ENCRYPTIONDIALOG_H
