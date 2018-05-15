#include "encryption_dialog.h"
#include "ui_dialog.h"

EncryptionDialog::EncryptionDialog(QWidget *parent)
    : QDialog(parent), ui(std::make_unique<Ui::Dialog>())
{
    ui->setupUi(this);
    this->setWindowTitle(tr("Message"));
    connect(ui->encrypt_button, SIGNAL(clicked()), this, SLOT(encrypt_clicked()));
    connect(ui->decrypt_button, SIGNAL(clicked()), this, SLOT(decrypt_clicked()));
    connect(ui->cancel_button, SIGNAL(clicked()), this, SLOT(close()));
}

EncryptionDialog::~EncryptionDialog()
{

}

void EncryptionDialog::set_text(const QString &text)
{
    ui->textEdit->setText(text);
}

void EncryptionDialog::encrypt_clicked()
{
    emit encrypt(ui->textEdit->toPlainText());
}

void EncryptionDialog::decrypt_clicked()
{
    emit decrypt(ui->textEdit->toPlainText());
}
