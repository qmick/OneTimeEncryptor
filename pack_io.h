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
    PackIO(const std::string &dst, const std::string &src);
    size_t read(void *buffer, size_t count);
    size_t write(const void *buffer, size_t count);
    int remove();
    bool eof() const;
    ~PackIO();

private:
    size_t buf_used;
    size_t buf_size;
    void *buf;

    FILE *current_file;
    FILE *dst_file;
    std::string dst_filename;
    bool is_eof;

    std::unique_ptr<archive> a;
    std::unique_ptr<archive> disk;
    std::unique_ptr<archive_entry> entry;

    void close();
};

#endif // PACK_IO_H
