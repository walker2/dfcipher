#ifndef DFCIPHER_DFC_H
#define DFCIPHER_DFC_H

#include <linux/in.h>
#include <utility>
#include <fstream>
#include "Key.h"

class DFC
{
public:
    explicit DFC() = default;


    void encryptFile(const std::string &path);

    void decryptFile(const std::string &path);

    /* Setters */
    void setKey(Key key);

    /* Getters */
    u32 *getTransKey() { return transKey; }

private:
    void encrypt(const std::vector<byte> &in, std::vector<byte> &out);

    void decrypt(const std::vector<byte> &in, std::vector<byte> &out);

    void cipherFile(const std::string &path, bool isEncryption);

    void setTransKey(Key in_key);

    void multMod64(u32 res[4], const u32 a[2], const u32 b[2]);

    void addMod64(u32 res[4], const u32 left, const u32 right);

    void multBy13(u32 res[3]);

    void roundFunc(const u32 in[2], u32 out[2], const u32 key[4]);

    void swapEndians(u32 first[4], u32 second[4], bool reverse = false);

    void readFile(std::vector<byte> &msg, const std::string &path);

    void writeFile(const std::vector<byte> &msg, const std::string &path);

private:
    u32 transKey[32]{};
};


#endif
