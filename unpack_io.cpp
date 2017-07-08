#include "unpack_io.h"
#include <pack_exception.h>
#include <archive.h>

using std::make_unique;

UnpackIO::UnpackIO(const std::string &dst, const std::string &src)
{
    a = make_unique<archive>(archive_read_new());
    ext = make_unique<archive>(archive_write_disk_new());
    archive_write_disk_set_options(ext.get(), ARCHIVE_EXTRACT_TIME);

//    if (archive_read_open_memor)
//        throw PackException(a.get());
}

size_t UnpackIO::read(void *buffer, size_t count)
{

}

size_t UnpackIO::write(const void *buffer, size_t count)
{

}

int UnpackIO::remove()
{

}

bool UnpackIO::eof() const
{

}

UnpackIO::~UnpackIO()
{

}
