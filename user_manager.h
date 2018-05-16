#ifndef USER_MANAGER_H
#define USER_MANAGER_H

#include <QString>
#include <memory>
#include <QMap>

namespace sqlite {
class DB;
}

struct User
{
    int id;
    QString name;
    int key_type;
    QString pubkey;
    QString private_key;
    QString digest;
    int64_t timestamp;
};

class UserManager
{
public:
    explicit UserManager(const QString &db_path);
    virtual ~UserManager();
    int count_users() const;
    QStringList get_all_usersname() const;
    QMap<QString, QString> get_user_digest() const;
    User get_user(const QString &username) const;
    User get_user() const;
    QString get_pubkey(const QString &username) const;
    QString get_pubkey() const;
    QString get_private_key(const QString &username) const;
    QString get_private_key() const;
    void set_pubkey(const QString &username, const QString &pubkey);
    void set_pubkey(const QString &pubkey);
    void set_private_key(const QString &username, const QString &private_key);
    void set_private_key(const QString &private_key);
    void set_key(const QString &username, const QString &pubkey, const QString &private_key);
    void set_key(const QString &pubkey, const QString &private_key);
    int get_key_type(const QString &username) const;
    int get_key_type() const;
    void add_user(const User &user);

    bool set_current_user(const QString &username);
    QString get_current_user() const;

private:
    std::unique_ptr<sqlite::DB> db;
    QString current_user;
};

#endif // USER_MANAGER_H
