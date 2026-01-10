#include "AES/aes_encryption/aes_encryption.h"
#include "src/util/util.h"
#include <iostream>

int main(int argc, char* argv[]){

    //
    if(argc == 3){
        std::string command(argv[1]);
        std::string target(argv[2]);

        if(command == "-e" || command == "--encrypt"){

            if(util::is_file_valid(target)){
                std::cout << "security key: ";

                std::string sec_key;
                std::cin >> sec_key;

                AesEncryption encryptor(target, sec_key);
            }
        }else if(command == "-d" || command == "--decrypt"){
        }
    }else if(argc > 3){
        std::cerr << "too many arguments" << "\n";
    }else{
        std::cerr << "too few arguements" << "\n";
    }
}
