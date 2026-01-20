#include "aes_encryption.h"
#include "src/AES/key_scheduler/key_scheduler.h"
#include "src/util/util.h"
#include <cmath>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <utility>
#include <vector>

//r1 - initial round key addition //first key is unedited the users pure secret key
//r9, 11 or 13 - subbytes, shift rows, mix columns add round key
//rfinal - subbytes shitrows addround key
//sample key: p7K9mR2vX4wQ8zN1

AesEncryption::AesEncryption(std::string file_path, std::string user_key){
    std::ifstream raw_file(file_path, std::ios::binary);


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
            aes_version = 128;
            num_rounds = 10;
            break;
        }

        default:{
            std::cerr << "invalid key length" << "\n";
            return;
        }
    }

    //generate key schedule in advance
   	KeyScheduler key_sch(user_key, aes_version);
	std::vector<std::vector<uint8_t>> expanded_key = key_sch.get_expanded_key();

	std::vector<std::vector<uint8_t>> crypt_buffer(4);

	//read and arrange 16 byte chunks of data into blocks
    while(raw_file.good()){

        //read block
        char buff[util::CHBUF_SIZ];

        raw_file.read(buff, util::CHBUF_SIZ);

        int bytes_read = raw_file.gcount();

        uint8_t state[4][4];
        int ctr = 0;

        while(ctr < bytes_read){
            util::reset_state(state);

            std::pair<int, int> row_col_pair;

            int rem = bytes_read - ctr;

            if(rem >= 16){
                char* beg = &buff[ctr];
                char* end = &buff[ctr + 15];
                ctr += 16;

                row_col_pair = util::populate_state(state, beg, end, 16);
            }else if(rem > 0 && rem < 16){

                char* beg = &buff[ctr];
                char* end = &buff[ctr + rem];

                row_col_pair = util::populate_state(state, beg, end, rem);

                //pad state if space
                pad_iso(
                    state, row_col_pair.first - 1,
                    row_col_pair.second);

                ctr = bytes_read;//end
            }



             // start encryption
            int round_ctr = 0;
            int k_end_pos = 0;//(key end position) is incremented by 4

            for(int round = 0; round <= num_rounds; round++){

                if(round == 0){//first round
                    add_round_key(state, expanded_key, k_end_pos);

                }else if(round > 0 && round < num_rounds){//mid
                    sub_bytes(state);
                    shift_rows(state);
                    mix_col(state);
                    add_round_key(state, expanded_key, k_end_pos);
                }else{//last
                    sub_bytes(state);
                    shift_rows(state);
                    add_round_key(state, expanded_key, k_end_pos);
                }
            }

        util::push_to_buffer(state, crypt_buffer);

        int buffer_size = crypt_buffer.size() * crypt_buffer[0].size();

        if(buffer_size == util::CHBUF_SIZ){//flush buffer if full
            util::flush_buffer(crypt_buffer, encr_file);
        }

    }

        //e at the end of file for some reason
        if(!crypt_buffer.empty()){
            util::flush_buffer(crypt_buffer, encr_file);//flush buffer one final time to clear reminants
        }

}


    raw_file.close();
    encr_file.close();

}


//reimplement galois field with official from document

void AesEncryption::shift_rows(uint8_t state[4][4]){
    // row 1: 0;
    // row 2: 1;
    // row 3: 2;
    // row 4: 1;

    //shift r2
    uint8_t fst = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = fst;

    //shift r3
    fst = state[2][0];
    uint8_t scnd = state[2][1];
    state[2][0] = state[2][2];
    state[2][1] = state[2][3];
    state[2][2] = fst;
    state[2][3] = scnd;

    //shift r4
    fst = state[3][0];
    scnd = state[3][1];
    uint8_t trd = state[3][2];
    state[3][0] = state[3][3];
    state[3][1] = fst;
    state[3][2] = scnd;
    state[3][3] = trd;
}

void AesEncryption::mix_col(uint8_t state[4][4]){
    uint8_t mix_state[4][4] = {{0x00}};// holds state after mix_column op

    for(int i = 0; i < 4; i++){
        mix_state[0][i] = (util::g_mul(0x02, state[0][i]) ^ util::g_mul(0x03, state[1][i]) ^ state[2][i] ^ state[3][i]);
        mix_state[1][i] = (state[0][i] ^ util::g_mul(0x02, state[1][i]) ^ util::g_mul(0x03, state[2][i]) ^ state[3][i]);
        mix_state[2][i] = (state[0][i] ^ state[1][i] ^ util::g_mul(0x02, state[2][i]) ^ util::g_mul(0x03, state[3][i]));
        mix_state[3][i] = (util::g_mul(0x03, state[0][i]) ^ state[1][i] ^ state[2][i] ^ util::g_mul(0x02, state[3][i]));
    }

    for(int row = 0; row < 4; row++){//return mix col result back to state
        for(int col = 0; col < 4; col++){
            state[row][col] = mix_state[row][col];
        }
    }
}


void AesEncryption::add_round_key(uint8_t mix_state[4][4], const std::vector<std::vector<uint8_t>> &expanded_key, int &k_end_pos){

    for(int row = 0; row < 4; row++){
        for(int col = 0; col < 4; col++){
            mix_state[row][col] =
                mix_state[row][col] ^ expanded_key[row][k_end_pos + col];
        }
    }

    k_end_pos += 4;
}

void AesEncryption::sub_bytes(uint8_t state[4][4]){

    for(int row = 0; row < 4; row++){
        for(int col = 0; col < 4; col++){
            std::pair<uint8_t, uint8_t> row_col_pair = util::separate(state[row][col]);
            //populate state with sbox mapped values
            state[row][col] = util::s_box[row_col_pair.first][row_col_pair.second];
        }
    }
}



void AesEncryption::pad_iso(uint8_t state[4][4], int last_row_pos, int last_col_pos){

    bool is_starting = true;
    for(int col = last_col_pos; col < 4; col++){

        if(is_starting){
            state[last_row_pos][last_col_pos] = 0x80;

            for(int row = last_row_pos + 1; row < 4; row++){
                state[row][col] = 0x00;
            }

            is_starting = false;
        }else{
            for(int row = 0; row < 4; row++){
                state[row][col] = 0x00;
            }
        }

    }
}
