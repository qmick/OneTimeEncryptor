#ifndef SECURE_MEMORY_H
#define SECURE_MEMORY_H

#include <memory>
#include <string>
#include <openssl/evp.h>

template <typename T>
class zallocator : public std::allocator<T>
{
public:
    typedef T value_type;
    typedef value_type* pointer;
    typedef const value_type* const_pointer;
    typedef value_type& reference;
    typedef const value_type& const_reference;
    typedef size_t size_type;
    typedef ptrdiff_t difference_type;

    zallocator() : allocator<T>() { }
    zallocator(const zallocator &a) : allocator<T>(a) { }
    template <class U>
    zallocator(const zallocator<U> &a) : allocator<T>(a) { }

    pointer address(reference v) const { return &v; }
    const_pointer address(const_reference v) const { return &v; }

    pointer allocate(size_type n, const void* hint = 0) {
        if (n > std::numeric_limits<size_type>::max() / sizeof(T))
            throw std::bad_alloc();
        return static_cast<pointer> (::operator new (n * sizeof(value_type)));
    }

    void deallocate(pointer p, size_type n) {
        OPENSSL_cleanse(p, n*sizeof(T));
        ::operator delete(p);
    }

    size_type max_size() const {
        return std::numeric_limits<size_type>::max() / sizeof(T);
    }

    template<typename U>
    struct rebind
    {
        typedef zallocator<U> other;
    };

    void construct(pointer ptr, const T& val) {
        new (static_cast<T*>(ptr)) T(val);
    }

    template<typename U, typename... Args>
    void construct(U* ptr, Args&&  ... args) {
        ::new (static_cast<void*> (ptr)) U(std::forward<Args>(args)...);
    }


    void destroy(pointer ptr) {
        static_cast<T*>(ptr)->~T();
    }

    template<typename U>
    void destroy(U* ptr) {
        ptr->~U();
    }
};


typedef unsigned char byte;
using std::shared_ptr;
typedef std::basic_string<char, std::char_traits<char>, zallocator<char> > secure_string;
using EVP_CIPHER_CTX_free_ptr = shared_ptr<EVP_CIPHER_CTX>;
using EVP_PKEY_free_ptr = shared_ptr<EVP_PKEY>;
using EVP_PKEY_CTX_free_ptr = shared_ptr<EVP_PKEY_CTX>;


class SecureBuffer
{
public:
    SecureBuffer();
    explicit SecureBuffer(size_t n);
    SecureBuffer(const byte *other, size_t n);
    SecureBuffer(const std::string &str);
    SecureBuffer(SecureBuffer &&other) noexcept;
    ~SecureBuffer();
    SecureBuffer &operator=(const SecureBuffer &other) = delete;
    SecureBuffer &operator=(SecureBuffer &&other) noexcept;
    byte &operator[](size_t n);
    const byte &operator[](size_t n) const;
    byte* get();
    size_t size();

private:
    size_t n;
    byte* buffer;
};


#endif // SECURE_MEMORY_H
