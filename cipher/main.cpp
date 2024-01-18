#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/sha.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/osrng.h>

using namespace CryptoPP;

void encrypt(const std::string& inputFile, const std::string& outputFile, const std::string& password) {
    // Создаем блок байтов для ключа шифрования
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);

    // Создаем объект PBKDF2 для выработки ключа из пароля
    PKCS12_PBKDF<SHA256> pbkdf;
    pbkdf.DeriveKey(key, key.size(), 0, (byte*)password.data(), password.size(), NULL, 0, 1024, 0.0f);

    // Создаем вектор инициализации
    byte iv[AES::BLOCKSIZE];
    AutoSeededRandomPool prng; // Создаем генератор случайных чисел
    prng.GenerateBlock(iv, sizeof(iv)); // Заполняем вектор инициализации случайными числами

    // Записываем IV в начало выходного файла
    std::ofstream out(outputFile.c_str(), std::ios::binary);
    out.write((char*)iv, sizeof(iv));

    // Шифруем файл
    CBC_Mode<AES>::Encryption enc(key, key.size(), iv);
    FileSource fs(inputFile.c_str(), true, 
                  new StreamTransformationFilter(enc, 
                  new FileSink(out)));
}

void decrypt(const std::string& inputFile, const std::string& outputFile, const std::string& password) {
    // Создаем блок байтов для ключа шифрования
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);

    // Создаем объект PBKDF2 для выработки ключа из пароля
    PKCS12_PBKDF<SHA256> pbkdf;
    pbkdf.DeriveKey(key, key.size(), 0, (byte*)password.data(), password.size(), NULL, 0, 1024, 0.0f);

    // Читаем IV из начала входного файла
    std::ifstream in(inputFile.c_str(), std::ios::binary);
    byte iv[AES::BLOCKSIZE];
    in.read((char*)iv, sizeof(iv));

    // Расшифровываем файл
    CBC_Mode<AES>::Decryption dec(key, key.size(), iv);
    FileSource fs(in, true, 
                  new StreamTransformationFilter(dec, 
                  new FileSink(outputFile.c_str())));
}

int main() {
    std::string mode, inputFile, outputFile, password;
    std::cout << "Введите режим работы (e(ncrypt)/d(ecrypt)): ";
    std::cin >> mode;
    std::cout << "Введите путь к входному файлу: ";
    std::cin >> inputFile;
    std::cout << "Введите путь к выходному файлу: ";
    std::cin >> outputFile;
    std::cout << "Введите пароль: ";
    std::cin >> password;
    if (mode == "e") {
        encrypt(inputFile, outputFile, password);
    } else if (mode == "d") {
        decrypt(inputFile, outputFile, password);
    } else {
        std::cout << "Неверный режим" << std::endl;
    }

    return 0;
}
