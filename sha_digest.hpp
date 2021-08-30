/**
 * @file sha_digest.hpp
 * @author Sunip K. Mukherjee (sunipkmukherjee@gmail.com)
 * @brief 
 * @version 0.1
 * @date 2021-08-25
 * 
 * @copyright Copyright (c) 2021
 * 
 */
#ifndef SHA_DIGEST_HPP
#define SHA_DIGEST_HPP

#include <openssl/sha.h>
#include <stdint.h>

class sha1_hash_t
{
private:
    void clear();
    unsigned int hash() const;
    uint8_t bytes[SHA512_DIGEST_LENGTH];

public:
    /**
     * @brief Construct a new empty SHA hash
     * 
     */
    sha1_hash_t();
    /**
     * @brief Construct a new SHA hash object and populate it with hash of input
     * 
     * @param str String to compute hash of 
     * @param len Length of string
     */
    sha1_hash_t(const char *str, size_t len);
    /**
     * @brief Get the pointer to SHA digest
     * 
     * @return const uint8_t* Pointer to SHA digest
     */
    const uint8_t *GetBytes() const;
    /**
     * @brief Copy a SHA hash to another SHA object
     * 
     * @param src 
     */
    void copy(sha1_hash_t *src);
    /**
     * @brief Verify if a SHA hash is valid
     * 
     * @return true Valid
     * @return false Invalid
     */
    bool valid() const;
    /**
     * @brief Check if two SHA hashes are equal
     * 
     * @param h SHA hash to compare against
     * @return true Equal
     * @return false Unequal
     */
    bool operator==(const sha1_hash_t &h) const;
    /**
     * @brief Check if two SHA hashes are unequal
     * 
     * @param h SHA hash to compare against
     * @return true Unequal
     * @return false Equal
     */
    bool operator!=(const sha1_hash_t &h) const;
};
#endif