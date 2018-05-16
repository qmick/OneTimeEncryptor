#include "user_manager.h"
#include "SQLiteCPP/DB.h"
#include <string>
#include <exception>
#include <QStringList>

UserManager::UserManager()
{

}

UserManager::UserManager(const QString &db_path)
{
    db = std::make_unique<sqlite::DB>(db_path.toStdString());
    std::string sql = "CREATE TABLE IF NOT EXISTS user("
                      "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                      "name TEXT NOT NULL, pubkey TEXT, private_key TEXT, digest TEXT,"
                      "Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP);";
    db->update(sql);
}

UserManager::~UserManager()
{

}

int UserManager::count_users() const
{
    std::string sql = "SELECT count(*) FROM user";
    auto stmt = db->query(sql);
    if (stmt.step() == sqlite::Statement::ROW)
        return stmt.column_int(0);
    else
        throw std::runtime_error("DB error");
}

QStringList UserManager::get_all_usersname() const
{
    std::string sql = "SELECT name FROM user";
    auto stmt = db->query(sql);
    QStringList user_list = QStringList();
    while (stmt.step() == sqlite::Statement::ROW)
        user_list.append(QString::fromStdString(stmt.column_string(0)));
    return user_list;
}

QMap<QString, QString> UserManager::get_user_digest() const
{
    std::string sql = "SELECT name, digest FROM user";
    auto stmt = db->query(sql);
    QMap<QString, QString> user_digest;
    while (stmt.step() == sqlite::Statement::ROW)
        user_digest[QString::fromStdString(stmt.column_string(0))] = QString::fromStdString(stmt.column_string(1));
    return user_digest;
}

User UserManager::get_user_by_name(const QString &username) const
{
    std::string sql = "SELECT * FROM user WHERE name=?";
    auto stmt = db->query(sql, username.toStdString());
    if (stmt.step() == sqlite::Statement::ROW)
    {
        User user;
        user.id = stmt.column_int(0);
        user.name = QString::fromStdString(stmt.column_string(1));
        user.pubkey = QString::fromStdString(stmt.column_string(2));
        user.private_key = QString::fromStdString(stmt.column_string(3));
        user.digest = QString::fromStdString(stmt.column_string(4));
        user.timestamp = stmt.column_int64(5);
        return user;
    }
    else
        throw std::runtime_error("Not such user");
}

QString UserManager::get_pubkey(const QString &username) const
{
    std::string sql = "SELECT pubkey FROM user WHERE name=?";
    auto stmt = db->query(sql, username.toStdString());
    if (stmt.step() == sqlite::Statement::ROW)
        return QString::fromStdString(stmt.column_string(0));
    else
        throw std::runtime_error("Not such user");
}

QString UserManager::get_private_key(const QString &username) const
{
    std::string sql = "SELECT private_key FROM user WHERE name=?";
    auto stmt = db->query(sql, username.toStdString());
    if (stmt.step() == sqlite::Statement::ROW)
        return QString::fromStdString(stmt.column_string(0));
    else
        throw std::runtime_error("Not such user");
}

void UserManager::add_user(const User &user)
{
    std::string sql = "INSERT INTO user(name,pubkey,private_key,digest) VALUES(?,?,?,?);";
    db->update(sql, user.name.toStdString(), user.pubkey.toStdString(),
               user.private_key.toStdString(), user.digest.toStdString());
}

void UserManager::set_pubkey(const QString &username, const QString &pubkey)
{
    std::string sql = "UPDATE user SET pubkey=? WHERE name=?";
    db->update(sql, pubkey.toStdString(), username.toStdString());
}

void UserManager::set_private_key(const QString &username, const QString &private_key)
{
    std::string sql = "UPDATE user SET private_key=? WHERE name=?";
    db->update(sql, private_key.toStdString(), username.toStdString());
}

void UserManager::set_key(const QString &username, const QString &pubkey, const QString &private_key)
{
    std::string sql = "UPDATE user SET pubkey=?,private_key=? WHERE name=?";
    db->update(sql, pubkey.toStdString(), private_key.toStdString(), username.toStdString());
}

int UserManager::get_key_type(const QString &username) const
{
    std::string sql = "SELECT key_type FROM user WHERE name=?";
    auto stmt = db->query(sql, username.toStdString());
    if (stmt.step() == sqlite::Statement::ROW)
    {
        return stmt.column_int(0);
    }
    else
        throw std::runtime_error("No such user");
}
