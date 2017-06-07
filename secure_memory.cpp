#include "secure_memory.h"

shared_ptr<byte> get_byte_shared(size_t n)
{
    return allocate_shared<byte>(zallocator<byte>(), n);
}
