#include "aes_decryption.h"
#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>
#include <sys/types.h>
#include <unordered_map>
#include <vector>
#include "src/AES/key_scheduler/key_scheduler.h"
#include "src/util/util.h"


AesDecryption::AesDecryption(std::string file_path, std::string user_key){
    std::ifstream raw_encr_file(file_path, std::ios::binary);

    std::ofstream decr_file(util::generate_out_path_decr(file_path));

    if(!raw_encr_file.is_open()){
        std::cerr << "error occurred while opening file" << "\n";
        return;
    }

    if(!decr_file.is_open()){
        std::cerr << "couldn't generate output folder" << "\n";
        return;
    }

    int length = user_key.length();

    int aes_version = 0;
    int num_rounds = 0;

    //len(key)/4+6
    switch (length) {
        case 16:{
            aes_version = 128;
            num_rounds = 10;
            break;
        }
        case 24:{
            aes_version = 192;
            num_rounds = 12;
            break;
        }

        case 32:{
            aes_version = 256;
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
    std::vector<std::vector<uint8_t>> decrypt_buffer(4);

    std::unordered_map<uint8_t, uint8_t> sub_map;
    //generate substitution table and substitute values of sbox with position values

    gen_sub_bytes(sub_map);

    while(raw_encr_file.good()){//edit

        //read block
        char buff[util::CHBUF_SIZ];

        raw_encr_file.read(buff, util::CHBUF_SIZ);

        int bytes_read = raw_encr_file.gcount();

        uint8_t state[4][4];
        int ctr = 0;

        while(ctr < bytes_read){
            util::reset_state(state);

            std::pair<int, int> row_col_pair;

            int rem = bytes_read - ctr;


            if(rem >= 16){//assumes padding / perfect alignment
                char* beg = &buff[ctr];
                char* end = &buff[ctr + 15];
                ctr += 16;

                row_col_pair = util::populate_state(state, beg, end, 16);
            }



             // start encryption
            int round_ctr = 0;
            int k_end_pos = (num_rounds * 4);//(final position) - 4;

            for(int round = num_rounds; round >= 0; round--){

                if(round == num_rounds){//first round
                    inv_add_round_key(state, expanded_key, k_end_pos);
                }else if(round > 0 && round < num_rounds){//middle rounds
                    inv_shift_rows(state);
                    inv_sub_bytes(state, sub_map);
                    inv_add_round_key(state, expanded_key, k_end_pos);
                    inv_mix_col(state);
                }else{//last_round
                    inv_shift_rows(state);
                    inv_sub_bytes(state, sub_map);
                    inv_add_round_key(state, expanded_key, k_end_pos);
                }
            }

            if(state[3][3] == 0x00 || state[3][3] == 0x80){//might be padded

                std::string content;
                std::string p_content;

                bool flag = false;
                bool is_padded = true;


                for(int col = 0; col < 4; col++){

                    for(int row = 0; row < 4; row++){

                        if(flag){
                            if(state[row][col] != 0x00){
                                is_padded = false;
                            }
                            p_content.push_back(state[row][col]);
                        }else{
                            if(state[row][col] == 0x80){
                                flag = true;
                                p_content.push_back(state[row][col]);
                            }else{
                                content.push_back(state[row][col]);
                            }

                        }


                    }
                }

                util::flush_buffer(decrypt_buffer, decr_file);//premature flush

                if(is_padded){
                    decr_file << content;
                }else{
                    decr_file << content << p_content;
                }
                continue;
            }

            util::push_to_buffer(state, decrypt_buffer);


            int buffer_size = decrypt_buffer.size() * decrypt_buffer[0].size();

            if(buffer_size == util::CHBUF_SIZ){//flush buffer if full
                util::flush_buffer(decrypt_buffer, decr_file);
            }

    }

        //e at the end of file for some reason
        if(!decrypt_buffer.empty()){
            util::flush_buffer(decrypt_buffer, decr_file);//flush buffer one final time to clear reminants
        }
}

    raw_encr_file.close();
    decr_file.close();
}

void AesDecryption::inv_sub_bytes(uint8_t state[4][4], std::unordered_map<uint8_t, uint8_t> &sub_map){

    for(int row = 0; row < 4; row++){
        for(int col = 0; col < 4; col++){
            state[row][col] = sub_map[state[row][col]];
        }
    }
}

void AesDecryption::inv_shift_rows(uint8_t state[4][4]){
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
    uint8_t fst = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = fst;

}

//xor twice to retrieve original value
void AesDecryption::inv_add_round_key(uint8_t state[4][4], const std::vector<std::vector<uint8_t>> &expanded_key, int &k_end_pos){
    for(int row = 0; row < 4; row++){
        for(int col = 0; col < 4; col++){
            state[row][col] = state[row][col] ^ expanded_key[row][k_end_pos + col];
        }
    }

    k_end_pos -= 4;
}

//sbox is 16x16
void AesDecryption::gen_sub_bytes(std::unordered_map<uint8_t, uint8_t> &sub_map){
    for(int row = 0; row < 16; row++){
        for(int col = 0; col < 16; col++){
            uint8_t val = util::combine(row, col);

            sub_map[util::s_box[row][col]] = val;
        }
    }
}

void AesDecryption::inv_mix_col(uint8_t state[4][4]){
    uint8_t mix_state[4][4] = {{0x00}};// holds state after mix_column op

    for(int i = 0; i < 4; i++){
        mix_state[0][i] = (util::g_mul(0x0E, state[0][i]) ^ util::g_mul(0x0B, state[1][i]) ^ util::g_mul(0x0D, state[2][i]) ^ util::g_mul(0x09 ,state[3][i]));
        mix_state[1][i] = (util::g_mul(0x09, state[0][i]) ^ util::g_mul(0x0E, state[1][i]) ^ util::g_mul(0x0B, state[2][i]) ^ util::g_mul(0x0D, state[3][i]));
        mix_state[2][i] = (util::g_mul(0x0D, state[0][i]) ^ util::g_mul(0x09, state[1][i]) ^ util::g_mul(0x0E, state[2][i]) ^ util::g_mul(0x0B, state[3][i]));
        mix_state[3][i] = (util::g_mul(0x0B, state[0][i]) ^ util::g_mul(0x0D, state[1][i]) ^ util::g_mul(0x09, state[2][i]) ^ util::g_mul(0x0E, state[3][i]));
    }

    for(int row = 0; row < 4; row++){//return mix col result back to state
        for(int col = 0; col < 4; col++){
            state[row][col] = mix_state[row][col];
        }
    }
}
