#ifndef FILE_DECRYPTOR_H
#define FILE_DECRYPTOR_H

#include <QString>

class Decryptor
{
public:
    Decryptor();
    size_t decrypt_file(const QString &filename);
};

#endif // FILE_DECRYPTOR_H
