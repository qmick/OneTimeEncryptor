#include "c_exception.h"
#include <cerrno>
#include <cstring>
#include <memory>


using std::make_unique;
using std::string;

CException::CException()
{
    auto err_str = strerror(errno);
    what_str = err_str;
}


CException::CException(const string &msg)
{
    auto err_str = strerror(errno);
    what_str = msg + ": " + err_str;
}


const char* CException::what() const noexcept
{
    return what_str.c_str();
}
