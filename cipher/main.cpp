#include <iostream>
#include <fstream>
#include <cryptopp/aes.h>
#include <cryptopp/ccm.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/modes.h>
#include <cryptopp/secblock.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/md5.h>

using namespace CryptoPP;

void DeriveKey(const std::string& password, SecByteBlock& derivedKey, SecByteBlock& iv) {
    const int KEY_SIZE = AES::DEFAULT_KEYLENGTH;
    const int IV_SIZE = AES::BLOCKSIZE;

    // Create MD5 hash from password
    MD5 hash;
    SecByteBlock digest(hash.DigestSize());
    hash.Update((const byte*)password.data(), password.size());
    hash.Final(digest);

    // Derive key and IV
    std::memcpy(derivedKey, digest, KEY_SIZE);
    std::memcpy(iv, digest + KEY_SIZE, IV_SIZE);
}

void EncryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& password) {
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    SecByteBlock iv(AES::BLOCKSIZE);

    DeriveKey(password, key, iv);

    CBC_Mode<AES>::Encryption encryption;
    encryption.SetKeyWithIV(key, key.size(), iv);

    FileSource fs(inputFile.c_str(), true, new StreamTransformationFilter(encryption, new FileSink(outputFile.c_str())));
}

void DecryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& password) {
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    SecByteBlock iv(AES::BLOCKSIZE);

    DeriveKey(password, key, iv);

    CBC_Mode<AES>::Decryption decryption;
    decryption.SetKeyWithIV(key, key.size(), iv);

    FileSource fs(inputFile.c_str(), true, new StreamTransformationFilter(decryption, new FileSink(outputFile.c_str())));
}

int main() {
    int choice;
    std::string inputFile, outputFile, password;

    std::cout << "Enter 1 for encryption or 2 for decryption: ";
    std::cin >> choice;

    std::cout << "Enter input file path: ";
    std::cin >> inputFile;

    std::cout << "Enter output file path: ";
    std::cin >> outputFile;

    std::cout << "Enter password: ";
    std::cin >> password;

    if (choice == 1) {
        EncryptFile(inputFile, outputFile, password);
        std::cout << "File encrypted successfully!" << std::endl;
    } else if (choice == 2) {
        DecryptFile(inputFile, outputFile, password);
        std::cout << "File decrypted successfully!" << std::endl;
    } else {
        std::cout << "Invalid choice. Please enter 1 or 2." << std::endl;
    }

    return 0;
}
