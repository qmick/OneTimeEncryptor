#ifndef ASYMMETRIC_CRYPTOR_H
#define ASYMMETRIC_CRYPTOR_H

#include <string>
#include <functional>
#include <cstdint>
#include <memory>

namespace Botan
{
    class Public_Key;
    class Private_Key;
}


class AsymmetricCryptor
{
public:
    static const std::string kCryptSign;

    AsymmetricCryptor();
    virtual ~AsymmetricCryptor();

    void load_public_key(const std::string &pubkey_file);
    void load_private_key(const std::string &prikey_file, const std::string &passphrase);

    /**
     * @brief Function that encrypt/decrypt file(s)
     * @param filename File(s) to be processed
     * @param callback Callback that used to send progress and recieve stop signal
     * @return
     */
    int64_t encrypt(const std::string &src, const std::string &dst,
                    std::function<bool(int64_t)> callback,
                    const std::string &cipher_name);

    int64_t decrypt(const std::string &src, const std::string &dst,
                    std::function<bool(int64_t)> callback,
                    const std::string &cipher_name);

private:
    std::unique_ptr<Botan::Public_Key> public_key;
    std::unique_ptr<Botan::Private_Key> private_key;

};


#endif // ASYMMETRIC_CRYPTOR_H
