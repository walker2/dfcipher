#include <iostream>
#include "DFC.h"

#define swapEndian(x)  __cpu_to_be32(x)
#define right4(x)   ((x) & 0x0000ffff)
#define left4(x)    ((x) >> 16)
#define bit(x, n)   ((1 << n) & x) != 0
#define CORRELATION

static const u32 ks[8] =
        {
                0xda06c80a, 0xbb1185eb, 0x4f7c7b57, 0x57f59584,
                0x90cfd47d, 0x7c19bb42, 0x158d9554, 0xf7b46bce,
        };

static const u32 ka[6] =
        {
                0xb7e15162, 0x8aed2a6a,
                0xbf715880, 0x9cf4f3c7,
                0x62e7160f, 0x38b4da56,
        };

static const u32 kb[6] =
        {
                0xa784d904, 0x5190cfef,
                0x324e7738, 0x926cfbe5,
                0xf4bf8d8d, 0x8c31d763,
        };

static const u32 kc = 0xeb64749a;

static const u32 kd[2] =
        {
                0x86d1bf27, 0x5b9b241d
        };

static const u32 rt[64] =
        {
                0xb7e15162, 0x8aed2a6a, 0xbf715880, 0x9cf4f3c7,
                0x62e7160f, 0x38b4da56, 0xa784d904, 0x5190cfef,
                0x324e7738, 0x926cfbe5, 0xf4bf8d8d, 0x8c31d763,
                0xda06c80a, 0xbb1185eb, 0x4f7c7b57, 0x57f59584,

                0x90cfd47d, 0x7c19bb42, 0x158d9554, 0xf7b46bce,
                0xd55c4d79, 0xfd5f24d6, 0x613c31c3, 0x839a2ddf,
                0x8a9a276b, 0xcfbfa1c8, 0x77c56284, 0xdab79cd4,
                0xc2b3293d, 0x20e9e5ea, 0xf02ac60a, 0xcc93ed87,

                0x4422a52e, 0xcb238fee, 0xe5ab6add, 0x835fd1a0,
                0x753d0a8f, 0x78e537d2, 0xb95bb79d, 0x8dcaec64,
                0x2c1e9f23, 0xb829b5c2, 0x780bf387, 0x37df8bb3,
                0x00d01334, 0xa0d0bd86, 0x45cbfa73, 0xa6160ffe,

                0x393c48cb, 0xbbca060f, 0x0ff8ec6d, 0x31beb5cc,
                0xeed7f2f0, 0xbb088017, 0x163bc60d, 0xf45a0ecb,
                0x1bcd289b, 0x06cbbfea, 0x21ad08e1, 0x847f3f73,
                0x78d56ced, 0x94640d6e, 0xf0d3d37b, 0xe67008e1,
        };


void DFC::encryptFile(const std::string &path)
{
    cipherFile(path, true);
}

void DFC::decryptFile(const std::string &path)
{
    cipherFile(path, false);
}

void DFC::setKey(Key key)
{
    setTransKey(key);
}

void DFC::encrypt(const std::vector<byte> &in, std::vector<byte> &out)
{
    u32 *key = transKey;
    auto *bIn = (u32 *) in.data();
    auto *bOut = (u32 *) out.data();
    u32 mes[4];

    /* Swap big and little endian */
    swapEndians(mes, bIn);

    /* Do the 8 rounds */

    roundFunc(mes, mes + 2, key + 0);
    roundFunc(mes + 2, mes, key + 4);
    roundFunc(mes, mes + 2, key + 8);
    roundFunc(mes + 2, mes, key + 12);

    roundFunc(mes, mes + 2, key + 16);
    roundFunc(mes + 2, mes, key + 20);
    roundFunc(mes, mes + 2, key + 24);
    roundFunc(mes + 2, mes, key + 28);

    swapEndians(bOut, mes, true);
}

void DFC::decrypt(const std::vector<byte> &in, std::vector<byte> &out)
{
    u32 *key = transKey;
    auto *bIn = (u32 *) in.data();
    auto *bOut = (u32 *) out.data();
    u32 mes[4];

    /* Swap big and little endian */
    swapEndians(mes, bIn);

    roundFunc(mes, mes + 2, key + 28);
    roundFunc(mes + 2, mes, key + 24);
    roundFunc(mes, mes + 2, key + 20);
    roundFunc(mes + 2, mes, key + 16);

    roundFunc(mes, mes + 2, key + 12);
    roundFunc(mes + 2, mes, key + 8);
    roundFunc(mes, mes + 2, key + 4);
    roundFunc(mes + 2, mes, key);

    swapEndians(bOut, mes, true);
}

void DFC::cipherFile(const std::string &path, bool isEncryption)
{
    std::vector<byte> message;
    std::vector<byte> result;

    readFile(message, path);

    size_t rem = 0;
    if (message.size() % 16 != 0)
    {
        rem = 16 - message.size() % 16;
    }

    for (auto i = 0; i < rem; ++i)
    {
        message.push_back(' ');
    }
    result.resize(message.size());

    for (int i = 0; i < message.size() / 16; ++i)
    {
        std::vector<byte> blockIn(16);
        std::vector<byte> blockOut(16);

        for (int j = 0; j < 16; ++j)
        {
            blockIn[j] = message[16 * i + j];
        }

        isEncryption ?
        encrypt(blockIn, blockOut) : decrypt(blockIn, blockOut);


        for (int j = 0; j < 16; ++j)
        {
            result[16 * i + j] = blockOut[j];
        }
    }

    /* DO CORRELATION */
#ifdef CORRELATION
    int onesIn = analyzeBits(message);
    int onesOut = analyzeBits(result);
    std::cout << "Src:\nOnes: " << onesIn << " Zeroes: " << (message.size() * 8) - onesIn << std::endl;
    std::cout << "Out:\nOnes: " << onesOut << " Zeroes: " << (result.size() * 8) - onesOut << std::endl;

    double correlation = correlationCoeff(message, result, onesIn, onesOut);
    std::cout << "Correlation coefficient is: " << correlation << std::endl;
#endif

    std::string addMsg = isEncryption ? "_encrypted" : "_decrypted";
    size_t lastdot = path.find_last_of('.');
    if (lastdot != std::string::npos)
    {
        std::string beforeDot = path.substr(0, lastdot);
        std::string afterDot = path.substr(lastdot, path.size() - 1);
        writeFile(result, beforeDot + addMsg + afterDot);
    } else
    {
        writeFile(result, path + addMsg);
    }
}

void DFC::setTransKey(Key in_key)
{
    u32 *input = (u32 *) in_key.getKey().data();
    u32 *roundKeys = transKey;

    size_t keyLength = 8 * in_key.getLength();

    u32 key[32];

    /* STEP 1: */

    /* Swap big to little endian */
    for (int i = 0; i < keyLength / 32; ++i)
    {
        key[i] = swapEndian(input[i]);
    }

    /* Complement K with KS const of 256 bit */

    for (int i = 0; i < 8 - keyLength / 32; ++i)
    {
        key[i + keyLength / 32] = ks[i];
    }

    /* STEP 2: */

    /* Reorder the key to create variables OA, OB, EA, EB       */
    /* Values would be stored like:                             */
    /*   OA[1], OB[2], ... , OA[i], OB[i + 1], ... , until 15   */
    /*   EA[1], EB[2], ... , EA[i], EB[i + 1], ... , until 31   */

    /* OA */
    key[0] = key[0];
    key[1] = key[7];

    /* OB */
    key[2] = key[4];
    key[3] = key[3];

    /* EA */
    key[16] = key[1];
    key[17] = key[6];

    /* EB */
    key[18] = key[5];
    key[19] = key[2];

    /* Set other elements by using 64 bit constants */

    for (int i = 0; i < 6; i += 2)
    {
        key[i + i + 4] = key[0] ^ ka[i];      /* OA[i] */
        key[i + i + 5] = key[1] ^ ka[i + 1];

        key[i + i + 6] = key[2] ^ kb[i];      /* OB[i] */
        key[i + i + 7] = key[3] ^ kb[i + 1];

        key[i + i + 20] = key[16] ^ ka[i];      /* EA[i] */
        key[i + i + 21] = key[17] ^ ka[i + 1];

        key[i + i + 22] = key[18] ^ kb[i];      /* EB[i] */
        key[i + i + 23] = key[19] ^ kb[i + 1];
    }

    /* After tleft4s we have two keys of 512 bit */
    /*    OK -- 0 ... 15 and EK -- 16 -- 31   */

    /* STEP 3: */

    u32 temp[4] = {0, 0, 0, 0};

    /* Do the 4 round of our round function */
    for (int i = 0; i < 32; i += 8)
    {
        roundFunc(temp, temp + 2, key);
        roundFunc(temp + 2, temp, key + 4);
        roundFunc(temp, temp + 2, key + 8);
        roundFunc(temp + 2, temp, key + 12);

        roundKeys[i + 0] = temp[2];
        roundKeys[i + 1] = temp[3];
        roundKeys[i + 2] = temp[0];
        roundKeys[i + 3] = temp[1];

        roundFunc(temp + 2, temp, key + 16);
        roundFunc(temp, temp + 2, key + 20);
        roundFunc(temp + 2, temp, key + 24);
        roundFunc(temp, temp + 2, key + 28);

        roundKeys[i + 4] = temp[0];
        roundKeys[i + 5] = temp[1];
        roundKeys[i + 6] = temp[2];
        roundKeys[i + 7] = temp[3];
    }

}

void DFC::multMod64(u32 *res, const u32 *a, const u32 *b)
{
    u32 x[4], y[4], t[4], c;

    /* Take individual numbers */
    x[0] = right4(a[1]);
    x[1] = left4(a[1]);
    x[2] = right4(a[0]);
    x[3] = left4(a[0]);

    y[0] = right4(b[1]);
    y[1] = left4(b[1]);
    y[2] = right4(b[0]);
    y[3] = left4(b[0]);

    t[0] = x[0] * y[0];
    res[0] = right4(t[0]);
    c = left4(t[0]);

    t[0] = x[0] * y[1];
    t[1] = x[1] * y[0];
    c += right4(t[0]) + right4(t[1]);
    res[0] += (c << 16);
    c = left4(c) + left4(t[0]) + left4(t[1]);

    t[0] = x[0] * y[2];
    t[1] = x[1] * y[1];
    t[2] = x[2] * y[0];
    c += right4(t[0]) + right4(t[1]) + right4(t[2]);
    res[1] = right4(c);
    c = left4(c) + left4(t[0]) + left4(t[1]) + left4(t[2]);

    t[0] = x[0] * y[3];
    t[1] = x[1] * y[2];
    t[2] = x[2] * y[1];
    t[3] = x[3] * y[0];
    c += right4(t[0]) + right4(t[1]) + right4(t[2]) + right4(t[3]);
    res[1] += (c << 16);
    c = left4(c) + left4(t[0]) + left4(t[1]) + left4(t[2]) + left4(t[3]);

    t[0] = x[1] * y[3];
    t[1] = x[2] * y[2];
    t[2] = x[3] * y[1];
    c += right4(t[0]) + right4(t[1]) + right4(t[2]);
    res[2] = right4(c);
    c = left4(c) + left4(t[0]) + left4(t[1]) + left4(t[2]);

    t[0] = x[2] * y[3];
    t[1] = x[3] * y[2];
    c += right4(t[0]) + right4(t[1]);
    res[2] += (c << 16);
    c = left4(c) + left4(t[0]) + left4(t[1]);

    res[3] = c + x[3] * y[3];
}

void DFC::addMod64(u32 *res, const u32 left, const u32 right)
{
    if ((res[0] += right) < right)
    {
        if (!++res[1])
        {
            if (!++res[2])
                ++res[3];
        }
    }

    if ((res[1] += left) < left)
    {
        if (!++res[2])
            ++res[3];
    }
}

void DFC::multBy13(u32 *res)
{
    u32 c, d;

    c = 13 * right4(res[0]);
    d = left4(res[0]);
    res[0] = right4(c);
    c = left4(c) + 13 * d;

    res[0] += (c << 16);
    c = left4(c) + 13 * right4(res[1]);
    d = left4(res[1]);
    res[1] = right4(c);
    c = left4(c) + 13 * d;

    res[1] += (c << 16);
    res[2] = left4(c);
}

void DFC::roundFunc(const u32 *in, u32 *out, const u32 *key)
{
    u32 result[5], b, t;


    multMod64(result, in, key);
    addMod64(result, key[2], key[3]);

    multBy13(&result[2]);

    t = result[0];
    result[0] -= result[2];
    b = (result[0] > t ? 1 : 0);

    t = result[1];
    result[1] -= result[3] + b;
    b = (result[1] > t ? 1 : (result[1] == t ? b : 0));

    b = 13 * (result[4] + b);  /* overflow into top 64 bits of acc */

    if (((result[0] += b) < b) && !(++result[1]))
    {
        if (result[0] > 12)
            result[0] -= 13;
    }

    /* do the confusion permutation */

    t = result[1] ^ kc;
    b = result[0] ^ rt[result[1] >> 26];

    b += kd[0] + ((t += kd[1]) < kd[1] ? 1 : 0);

    out[0] ^= b;
    out[1] ^= t;
}

void DFC::swapEndians(u32 *first, u32 *second, bool reverse)
{
    if (!reverse)
    {
        first[0] = swapEndian(second[0]);
        first[1] = swapEndian(second[1]);
        first[2] = swapEndian(second[2]);
        first[3] = swapEndian(second[3]);
    } else
    {
        first[0] = swapEndian(second[2]);
        first[1] = swapEndian(second[3]);
        first[2] = swapEndian(second[0]);
        first[3] = swapEndian(second[1]);
    }
}

void DFC::readFile(std::vector<byte> &msg, const std::string &path)
{
    FILE *f = fopen(path.c_str(), "rb");
    int c;

    while ((c = getc(f)) != EOF)
    {
        msg.push_back((byte) c);
    }
}

void DFC::writeFile(const std::vector<byte> &msg, const std::string &path)
{
    std::ofstream out(path);

    for (auto b : msg)
    {
        out << b;
    }

    out.close();
}

double DFC::correlationCoeff(const std::vector<byte> &in, const std::vector<byte> &out, int onesIn, int onesOut)
{
    double result = 0;

    double partOnesIn = onesIn / (in.size() * 8.);
    double partOnesOut = onesOut / (out.size() * 8.);
    double numerator = 0;
    double denomerator = 0;
    double squareX = 0;
    double squareY = 0;

    for (int i = 0; i < in.size(); i++) {
        for (int j = 0; j < 8; j++) {
            double x = bit(in[i], j);
            double y = bit(out[i], j);
            numerator += (x - partOnesIn) * (y - partOnesOut);
            squareX += x * x;
            squareY += y * y;
        }
    }

    denomerator = sqrt(squareX * squareY);

    result = numerator / denomerator;

    return result;

}

double DFC::getMedian(const std::vector<byte> &in)
{
    double a = 0;
    for (auto i : in)
    {
        int ch = 1;
        while (ch < 256)
        {
            a += ch & i;
            ch <<= 1;
        }
    }
    return a / (in.size() * 8);
}

int DFC::analyzeBits(const std::vector<byte> &message)
{
    int counter = 0;

    for (int i = 0; i < message.size(); i++) {
        counter += countOnes(message[i]);
    }

    return counter;
}

int DFC::countOnes(uint8_t byte) {
    int counter = 0;

    for (int i = 0; i < 8; i++) {
        if (((1 << i) & byte) != 0) {
            counter++;
        }
    }

    return counter;
}