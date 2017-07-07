#include "pack_io.h"
#include "pack_exception.h"
#include "c_exception.h"
#include <archive.h>
#include <archive_entry.h>

using std::string;
using std::make_unique;

PackIO::PackIO(const string &dst, const std::string &src, void *buf, size_t buf_size)
    : buf(buf), buf_size(buf_size), current_file(nullptr), is_eof(false)
{
    a = make_unique<archive>(archive_write_new());
    archive_write_add_filter_none(a.get());
    archive_write_set_format_ustar(a.get());
    archive_write_open_memory(a, buf, buf_size, &buf_used);

    disk = make_unique<archive>(archive_read_disk_new());
    if (archive_read_disk_open(disk.get(), src.c_str()) != ARCHIVE_OK)
        throw PackException(disk.get());
}

size_t PackIO::read(void *buffer, size_t size, size_t count)
{
    size_t total_len = 0;
    SecureBuffer read_buf(size * count);

    while (!is_eof && total_len < size * count)
    {
        if (!current_file || feof(current_file))
        {
            auto r = archive_read_next_header2(disk.get(), entry.get());
            if (r == ARCHIVE_EOF)
            {
                is_eof = true;
                return total_len;
            }

            if (r != ARCHIVE_OK)
                throw PackException(disk.get());

            archive_read_disk_descend(disk.get());
            r = archive_write_header(a.get(), entry.get());
            if (r < ARCHIVE_OK || r == ARCHIVE_FATAL)
                throw PackException(a.get());

            current_file = fopen(archive_entry_sourcepath(entry.get()), "rb");
            if (!current_file)
                throw CException();
        }
        auto len = fread()
    }
    return total_len;
}

size_t PackIO::write(const void *buffer, size_t, size_t count)
{

}

bool PackIO::eof()
{

}
