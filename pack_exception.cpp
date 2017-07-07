#include "pack_exception.h"
#include <archive.h>

using std::string;

PackException::PackException(archive *a)
{
    what_str = archive_error_string(a);
}

PackException::PackException(const std::string &msg, archive *a)
{
    what_str =
}
