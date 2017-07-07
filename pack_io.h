#ifndef PACK_IO_H
#define PACK_IO_H

#include "secure_memory.h"
#include <string>
#include <memory>

struct archive;
struct archive_entry;

class PackIO
{
public:
    PackIO(const std::string &dst, const std::string &src, void *buf, size_t buf_size);
    size_t read(void *buffer, size_t size, size_t count);
    size_t write(const void *buffer, size_t, size_t count);
    bool eof();

private:
    size_t buf_used;
    size_t buf_size;
    void *buf;

    FILE *current_file;
    bool is_eof;

    std::unique_ptr<archive> a;
    std::unique_ptr<archive> disk;
    std::unique_ptr<archive_entry> entry;
};

#endif // PACK_IO_H
