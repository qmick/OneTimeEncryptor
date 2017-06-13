#include "c_exception.h"
#include <cerrno>
#include <cstring>
#include <memory>


CException::CException()
{
    auto buf = std::shared_ptr<char>(new char[kMaxErrorStringLen + 1], std::default_delete<char[]>());
    strerror_s(buf.get(), kMaxErrorStringLen, errno);
    what_str = buf.get();
}


CException::CException(const std::string &msg)
{
    auto buf = std::shared_ptr<char>(new char[kMaxErrorStringLen + 1], std::default_delete<char[]>());
    strerror_s(buf.get(), kMaxErrorStringLen, errno);
    what_str = msg + buf.get();
}


const char* CException::what() const noexcept
{
    return what_str.c_str();
}
