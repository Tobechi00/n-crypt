#include "key_scheduler.h"
#include "src/util/util.h"
#include <cstdint>
#include <sys/types.h>
#include <vector>

KeyScheduler::KeyScheduler(std::string user_key, int aes_ver){
    this -> expanded_key = std::vector<std::vector<uint8_t>> (4);

    this -> rcon_val = 0x01;

    int key_size = aes_ver/4;

    if(key_size <= 6){
        //arranged in column major order

        int ptr = 0; //(do depending on size) on each round (like each round divisible by key size
        //ie key 12 for aes 6 we perform all the core functions but for rounds that are not we just
        // perform key xor key ie k7 = k6 xor k1)
        // https://crypto.stackexchange.com/questions/51951/aes-key-expansion-for-192-bit

        for(int col = 0; col < key_size; col++){

            for(int row = 0; row < 4; row++){

                expanded_key[row].push_back(user_key[ptr]);
                ptr++;
            }
        }

        // adadadadadadadad
        //stopped

        int curr_num_col = key_size;
        int req_num_col = 0;

        if(key_size == 4){
            req_num_col = 44;
        }else{
            req_num_col = 52;
        }


        while (curr_num_col < req_num_col) {

            std::vector<uint8_t> last_col;

            //emplace last column in last_col
            emplace(last_col, expanded_key, curr_num_col - 1);


            //rotate, substitute, apply round constant
            rot_word(last_col);
            sub_word(last_col);
            op_rcon(last_col);

            int op_pos = curr_num_col - key_size;//inc forward depending on key size

            for(int i = 0; i < key_size; i++){

                for(int i = 0; i < 4; i++){
                    last_col[i] = last_col[i] ^ expanded_key[i][op_pos];
                }

                op_pos++;

                //push back operated value
                for(int i = 0; i < 4; i++){
                    expanded_key[i].push_back(last_col[i]);
                }
                curr_num_col++;
            }


        }


    }else{//256 differs apply subword every multiple of 4

    }
}

void KeyScheduler::rot_word(std::vector<uint8_t> &word){
    uint8_t temp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = temp;
}

void KeyScheduler::sub_word(std::vector<uint8_t> &word){
    for(int i = 0; i < word.size(); i++){
        std::pair<int, int> row_col_pair = util::separate(word[i]);
        word[i] = util::s_box[row_col_pair.first][row_col_pair.second];
    }
}

void KeyScheduler::op_rcon(std::vector<uint8_t> &word){
    word[0] *= this -> rcon_val;
    if((this -> rcon_val >= 1) && (this -> rcon_val < 0x80)){//2 . RC
        this -> rcon_val *= 2;
    }else if(this -> rcon_val >= 0x80){//(2 . RC) ^ 0X11B
        this -> rcon_val = (this -> rcon_val * 2) ^ 0x11B;
    }
}

std::vector<std::vector<uint8_t>> &KeyScheduler::get_expanded_key(){
    return this -> expanded_key;
}

void KeyScheduler::emplace(
    std::vector<uint8_t> &last_col,
    std::vector<std::vector<uint8_t>> &expanded_key,
    int fin_pos
){
    for(int i = 0; i < 4; i++){
        last_col.push_back(expanded_key[i][fin_pos]);
    }
}
