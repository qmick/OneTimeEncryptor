#ifndef PACK_EXCEPTION_H
#define PACK_EXCEPTION_H

#include <string>
#include <exception>

struct archive;

class PackException : public virtual std::exception
{
public:
    explicit PackException(archive *a);
    PackException(const std::string &msg, archive *a);
    virtual const char* what() const noexcept;

private:
    std::string what_str;
};

#endif // PACK_EXCEPTION_H
