#include "c_exception.h"
#include <cerrno>
#include <cstring>
#include <memory>


using std::shared_ptr;
using std::string;
using std::default_delete;

CException::CException()
{
    auto buf = shared_ptr<char>(new char[kMaxErrorStringLen + 1], default_delete<char[]>());
    strerror_s(buf.get(), kMaxErrorStringLen, errno);
    what_str = buf.get();
}


CException::CException(const string &msg)
{
    auto buf = shared_ptr<char>(new char[kMaxErrorStringLen + 1], default_delete<char[]>());
    strerror_s(buf.get(), kMaxErrorStringLen, errno);
    what_str = msg + buf.get();
}


const char* CException::what() const noexcept
{
    return what_str.c_str();
}
