#include "c_exception.h"
#include <cerrno>
#include <cstring>
#include <memory>


using std::make_unique;
using std::string;

CException::CException()
{
    what_str = strerror(errno);
}


CException::CException(const string &msg)
{
    what_str = msg + strerror(errno);
}


const char* CException::what() const noexcept
{
    return what_str.c_str();
}
