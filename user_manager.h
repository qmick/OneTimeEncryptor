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
    UserManager();
    explicit UserManager(const QString &db_path);
    virtual ~UserManager();
    int count_users() const;
    QStringList get_all_usersname() const;
    QMap<QString, QString> get_user_digest() const;
    User get_user_by_name(const QString &username) const;
    QString get_pubkey(const QString &username) const;
    QString get_private_key(const QString &username) const;
    void set_pubkey(const QString &username, const QString &pubkey);
    void set_private_key(const QString &username, const QString &private_key);
    void set_key(const QString &username, const QString &pubkey, const QString &private_key);
    int get_key_type(const QString &username) const;
    void add_user(const User &user);


private:
    std::unique_ptr<sqlite::DB> db;
};

#endif // USER_MANAGER_H
