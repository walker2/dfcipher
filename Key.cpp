#include "Key.h"
Key::Key(std::size_t size)
{
    assert(size <= 32);
    generateRandom(size);
}

Key::Key(const std::vector<byte> &_key)
{
    setKey(key);
}

void Key::generateRandom(std::size_t size)
{
    key.resize(size);
    randomize();
}

void Key::setKey(const std::vector<byte> &_key)
{
    assert(key.size() <= 32);
    key = key;
}

void Key::randomize()
{
    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<byte> dist(0, 255);

    for (int i = 0; i < key.size(); ++i)
    {
        key[i] = dist(mt);
    }
}

