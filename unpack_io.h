#ifndef UNPACK_IO_H
#define UNPACK_IO_H

#include <string>
#include <memory>


struct archive;
struct archive_entry;

class UnpackIO
{
public:
    UnpackIO(const std::string &dst, const std::string &src);
    size_t read(void *buffer, size_t count);
    size_t write(const void *buffer, size_t count);
    int remove();
    bool eof() const;
    ~UnpackIO();

private:
    FILE *dst_file;
    std::string dst_filename;
    bool is_eof;

    std::unique_ptr<archive> a;
    std::unique_ptr<archive> ext;
    std::unique_ptr<archive_entry> entry;
};

#endif // UNPACK_IO_H
