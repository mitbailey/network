#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>
#include "sha_digest.hpp"

void sha1_hash_t::clear()
{
    memset(bytes, 0, sizeof(bytes));
}

sha1_hash_t::sha1_hash_t()
{
    clear();
}

sha1_hash_t::sha1_hash_t(const char *str, size_t len)
{
    clear();
    if (str != NULL && str != nullptr && len > 0)
    {
        SHA512((const unsigned char *) str, len, bytes);
    }
}

unsigned int sha1_hash_t::hash() const
{
    unsigned int result = 0;
    for (int i = sizeof(bytes); i > 0; i--)
        result |= bytes[i];
    return result;
}

bool sha1_hash_t::valid() const
{
    if (!hash())
        return false;
    return true;
}

void sha1_hash_t::copy(sha1_hash_t *src)
{
    if (src != NULL && src != nullptr)
        memcpy(bytes, src->bytes, sizeof(bytes));
}

bool sha1_hash_t::operator==(const sha1_hash_t &h) const
{
    bool result = true;
    for (int i = 0; i < sizeof(bytes); i++)
        if (bytes[i] != h.bytes[i])
        {
            result = false;
            break;
        }
    return result;
}

bool sha1_hash_t::operator!=(const sha1_hash_t &h) const
{
    return !(*this == h);
}

const uint8_t *sha1_hash_t::GetBytes() const
{
    return bytes;
}
