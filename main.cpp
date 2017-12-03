#include <iostream>
#include <cstring>
#include "Key.h"
#include "DFC.h"

int main(int argv, char **argc)
{
    DFC dfc;
    Key key;
    int nextArg = 0;
    bool encryption = true;
    if (std::strcmp(argc[1], "-e") == 0)
    {
        encryption = true;
    } else if (std::strcmp(argc[1], "-d") == 0)
    {
        encryption = false;
    } else
    {
        std::cout << "Please, use flag -e/-d to encode/decode file";
        return 1;
    }

    if (std::strcmp(argc[2], "-r") == 0)
    {
        switch (std::atoi(argc[3]))
        {
            case 128:
                key.generateRandom(16);
                break;
            case 192:
                key.generateRandom(24);
                break;
            case 256:
                key.generateRandom(32);
                break;
            default:
                key.generateRandom(std::atoi(argc[3]) / (size_t) 8);
                break;
        }
        nextArg = 4;
    } else
    {
        std::string str = argc[2];
        std::vector<byte> k(str.length());
        for (int i = 0; i < str.length(); ++i)
        {
            k[i] = static_cast<unsigned char>(str[i]);
        }
        key.setKey(k);
        nextArg = 3;
    }

    dfc.setKey(key);
    std::string filePath = argc[nextArg];
    encryption ? dfc.encryptFile(filePath) : dfc.decryptFile(filePath);

    std::cout << "\nDONE";
    return 0;
}