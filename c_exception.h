#ifndef C_EXCEPTION_H
#define C_EXCEPTION_H

#include <exception>
#include <string>

class CException : public std::exception
{
public:
    static const int kMaxErrorStringLen = 256;
    CException();
    explicit CException(const std::string &msg);
    virtual const char* what() const noexcept;

private:
    std::string what_str;
};

#endif // C_EXCEPTION_H
