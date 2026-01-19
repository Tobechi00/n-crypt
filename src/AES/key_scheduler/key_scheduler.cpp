#include "key_scheduler.h"
#include "src/util/util.h"
#include <cstdint>
#include <sys/types.h>
#include <vector>

KeyScheduler::KeyScheduler(std::string user_key, int aes_ver){
    this -> expanded_key = std::vector<std::vector<uint8_t>> (4);

    this -> rcon_val = 0x01;

    //arranged in column major order
    //place original key
    int ptr = 0;
    for(int col = 0; col < 4; col++){

        for(int row = 0; row < 4; row++){

            expanded_key[row].push_back(static_cast<uint8_t>(user_key[ptr]));
            ptr++;
        }
    }


    std::vector<uint8_t> r_const;

    for(int m_col = 4; m_col < 44; m_col++){

        if(m_col % 4 == 0){
            gen_round_const(r_const);

            std::vector<uint8_t> last_col;

            //emplace last column in last_col
            emplace(last_col, expanded_key, m_col - 1);


            //rotate, substitute, apply round constant
            rot_word(last_col);
            sub_word(last_col);
            op_rcon(last_col, r_const);


            for(int row = 0; row < 4; row++){
                expanded_key[row].push_back(last_col[row] ^ expanded_key[row][m_col - 4]);
            }
        }else{
            for(int row = 0; row < 4; row++){
                expanded_key[row].push_back(expanded_key[row][m_col - 1] ^ expanded_key[row][m_col - 4]);
            }
        }
    }
}

//shift once
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

//first r constant already added generate off first
//storing all round constants, not needed but ill leave it for now
void KeyScheduler::gen_round_const(std::vector<uint8_t> &r_const){

    if(r_const.empty()){
        r_const = {0x01, 0x00, 0x00, 0x00};
    }else{
        std::vector<uint8_t> next = {0x00, 0x00, 0x00, 0x00};

        next[0] = util::g_mul(r_const[0], 2);
        r_const = next;
    }
}

void KeyScheduler::op_rcon(std::vector<uint8_t> &word, std::vector<uint8_t> &r_const){
    for(int i = 0; i < word.size(); i++){
        word[i] = word[i] ^ r_const[i];
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
