#include "aes_decryption.h"
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <sys/types.h>
#include <unordered_map>
#include "src/AES/key_scheduler/key_scheduler.h"
#include "src/util/util.h"

const std::vector<std::vector<uint8_t>> AesDecryption::inv_mix_col_mat = {
    {0x0E, 0x0B, 0x0D, 0x09},
    {0x09, 0x0E, 0x0B, 0x0D},
    {0x0D, 0x09, 0x0E, 0x0B},
    {0x0B, 0x0D, 0x09, 0x0E}
};

const std::vector<int> AesDecryption::poly_rs_8 = {4, 3, 1, 0};

//TODO finish inverse mix and implement reverse rounds
AesDecryption::AesDecryption(std::string file_path, std::string user_key){
    std::ifstream raw_file(file_path, std::ios::binary);

    std::filesystem::path p = file_path;

    std::ofstream encr_file(util::generate_out_path(file_path));


    //file is empty??
    if(!raw_file.is_open()){
        std::cerr << "error occurred while opening file" << "\n";
        return;
    }

    if(!encr_file.is_open()){
        std::cerr << "couldn't generate output folder" << "\n";
        return;
    }

    int length = user_key.length();

    int aes_version = 0;
    int num_rounds = 0;

    //len(key)/4+6
    switch (length) {
        case 16:{
            aes_version = 16;
            num_rounds = 10;
            break;
        }
        case 24:{
            aes_version = 24;
            num_rounds = 12;
            break;
        }

        case 32:{
            aes_version = 32;
            num_rounds = 14;
            break;
        }

        default:{
            std::cerr << "invalid key length" << "\n";
            return;
        }
    }

    KeyScheduler key_scheduler(user_key, aes_version);

    std::vector<std::vector<uint8_t>> expanded_key = key_scheduler.get_expanded_key();

    std::unordered_map<uint8_t, uint8_t> sub_map;
    //generate substitution table and substitute values of sbox with position values
    gen_sub_bytes(sub_map);



}

void AesDecryption::inv_sub_bytes(char state[4][4], std::unordered_map<uint8_t, uint8_t> &sub_map){

    for(int row = 0; row < 4; row++){
        for(int col = 0; col < 4; col++){
            state[row][col] = sub_map[state[row][col]];
        }
    }
}

void AesDecryption::inv_shift_rows(char state[4][4]){
    // row 1: 0;
    // row 2: 1;
    // row 3: 2;
    // row 4: 1;

    //inv shift r2
    uint8_t lst = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = lst;

    //inv shift r3
    lst = state[2][3];
    uint8_t snd_lst = state[2][2];
    state[2][3] = state[2][1];
    state[2][2] = state[2][0];
    state[2][1] = lst;
    state[2][0] = snd_lst;


    //inv shift r4
    lst = state[3][3];
    state[3][3] = state[3][0];
    state[3][0] = lst;

}

//xor twice to retrieve original value
void AesDecryption::inv_add_round_key(char state[4][4], const std::vector<std::vector<uint8_t>> &expanded_key, int &k_end_pos){
    for(int row = 0; row < 4; row++){
        for(int col = 0; col < 4; col++){
            state[row][col] = state[row][col] ^ expanded_key[row][k_end_pos + col];
        }
    }

    k_end_pos--;//kp above 0
}

//sbox is 16x16
void AesDecryption::gen_sub_bytes(std::unordered_map<uint8_t, uint8_t> &sub_map){
    for(int row = 0; row < 16; row++){
        for(int col = 0; col < 16; row++){
            uint8_t val = util::combine(row, col);

            sub_map[util::s_box[row][col]] = val;
        }
    }
}

uint8_t AesDecryption::inv_mix_col(uint8_t inv_val, uint8_t state_val){
    //g(2^3) == 8
        if(inv_val == 0x01){//multiplying by 1 nets you the same value
            return state_val;
        }

        std::vector<int> field_non_z;
        std::vector<int> state_non_z;

        std::uint8_t mask = 0x80; //10000000

        //use mask to check if each bit is set in both values
        for(int i = 7; i >= 0; i--){

            uint8_t field_op = inv_val | mask;
            uint8_t state_op = state_val | mask;

            if(inv_val == field_op){
                field_non_z.push_back(i);
            }

            if(state_val == state_op){
                state_non_z.push_back(i);
            }


            mask = mask >> 1;//shift mask bit backwards
        }


        std::map<int, int> mul_val;//discard all keys with non one values/ cancel all values with duplicates out

        //irreducible polynomial theorem for values greater than 7 (==8) after addition, reduce to: x^4 + x^3 + x + 1
        //where these values  reflect the bit positions which are set

        //multiply all values of field with values of state
        for(int f_val : field_non_z){

            for(int s_val : state_non_z){
                int res = f_val + s_val;

                if(res == 8){//irreducable polynomial theorem
                    for(int i : poly_rs_8){
                        mul_val[i]++;
                    }
                }else{
                    mul_val[res]++;
                }
            }
        }
        //field_non_z * state_non_z;

        uint8_t fin_val = 0x00;

        for(const auto pair : mul_val){
            uint8_t mask = 0x01;//00000001

            if(pair.second % 2 != 0){//all with an even number of keys cross each other, odd keys have a reminant
                mask = mask << pair.first;
                fin_val = fin_val | mask;
            }
        }

        return fin_val;
}
