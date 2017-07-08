#include "pack_io.h"
#include "pack_exception.h"
#include "c_exception.h"
#include <archive.h>
#include <archive_entry.h>
#include <cassert>

using std::string;
using std::make_unique;

PackIO::PackIO(const string &dst, const std::string &src)
    : current_file(nullptr), dst_file(nullptr),
      dst_filename(dst), is_eof(false), buf_used(0)
{
    a = make_unique<archive>(archive_write_new());
    archive_write_add_filter_none(a.get());
    archive_write_set_format_ustar(a.get());
    archive_write_open_memory(a.get(), buf, buf_size, &buf_used);

    disk = make_unique<archive>(archive_read_disk_new());
    if (archive_read_disk_open(disk.get(), src.c_str()) != ARCHIVE_OK)
        throw PackException(disk.get());

    dst_file = fopen(dst.c_str(), "wb");
    if (!dst_file)
        throw CException();
}

size_t PackIO::read(void *buffer, size_t count)
{
    size_t total_len = 0;
    SecureBuffer read_buf(count);

    while (!is_eof && total_len < count)
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
            total_len += buf_used;

            current_file = fopen(archive_entry_sourcepath(entry.get()), "rb");
            if (!current_file)
                throw CException();
        }
        auto len = fread(read_buf.get(), 1, count, current_file);
        if (ferror(current_file))
            throw CException();
        while (len > 0)
        {
            len = fread(read_buf.get(), 1, count, current_file);
            if (ferror(current_file))
                throw CException();
            archive_write_data(a.get(), read_buf.get(), len);
            assert(buf_used < len);
            total_len += buf_used;
        }
    }
    return total_len;
}

size_t PackIO::write(const void *buffer, size_t count)
{
    auto len = fwrite(buffer, 1, count, dst_file);
    if (len != count)
        throw CException("cannot write");

    return len;
}

int PackIO::remove()
{
    close();
    return ::remove(dst_filename.c_str());
}

bool PackIO::eof() const
{
    return is_eof;
}

PackIO::~PackIO()
{
    close();
}

void PackIO::close()
{
    if (current_file)
        fclose(current_file);
    if (dst_file)
        fclose(dst_file);
}
