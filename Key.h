#ifndef DFCIPHER_KEY_H
#define DFCIPHER_KEY_H

#include <cstdint>
#include <vector>
#include <cassert>
#include <random>

typedef std::uint32_t u32;
typedef std::uint8_t byte;

class Key
{
public:
    explicit Key() = default;

    explicit Key(std::size_t size);

    explicit Key(const std::vector<byte> &_key);

    void generateRandom(std::size_t size);

    /* Setters */
    void setKey(const std::vector<byte> &_key);

    /* Getters */
    std::vector<byte> getKey() { return key; }

    size_t getLength() { return key.size(); }

private:
    void randomize();

private:
    std::vector<byte> key;
};


#endif
