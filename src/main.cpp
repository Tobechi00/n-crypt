#include "AES/aes_encryption/aes_encryption.h"
#include "src/AES/aes_decryption/aes_decryption.h"
#include "src/util/util.h"
#include <iostream>

int main(int argc, char* argv[]){

    if(argc == 3){
        std::string command(argv[1]);
        std::string target(argv[2]);

        if(!util::is_file_valid(target)){
            std::cerr << "couldn't open target file";
            return 1;
        }

        if(command == "-e" || command == "--encrypt"){

            std::cout << "security key: ";

            std::string sec_key;
            std::cin >> sec_key;

            AesEncryption encryptor(target, sec_key);

        }else if(command == "-d" || command == "--decrypt"){
            std::cout << "security key: ";

            std::string sec_key;
            std::cin >> sec_key;

            AesDecryption decryptor(target, sec_key);
        }
    }else if(argc > 3){
        std::cerr << "too many arguments" << "\n";
    }else{
        std::cerr << "too few arguements" << "\n";
    }
}
