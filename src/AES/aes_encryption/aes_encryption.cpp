#include "aes_encryption.h"
#include "src/AES/key_scheduler/key_scheduler.h"
#include "src/util/util.h"
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <utility>
#include <vector>

//r1 - initial round key addition //first key is unedited the users pure secret key
//r9, 11 or 13 - subbytes, shift rows, mix columns add round key
//rfinal - subbytes shitrows addround key
//sample key: mNpQ2zR8xV4kL7aB9jY5sT1w
const std::vector<int>AesEncryption::poly_rs_8 = {4, 3, 1, 0};

const std::vector<std::vector<uint8_t>> AesEncryption::galois_field = {
    {0x02, 0x03, 0x01, 0x01},
    {0x01, 0x02, 0x03, 0x01},
    {0x01, 0x01, 0x02, 0x03},
    {0x03, 0x01, 0x01, 0x02}
};

AesEncryption::AesEncryption(std::string file_path, std::string user_key){
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

    //TODO
    //fix buffer, extra text being appended at end and incorrect text on file
    // check pkcs algo

    //use PKCS#7 to pad block if not enough bytes
    // padding is determined based on the number of unfilled bytes (ie if 9 bytes 0x09)

    //16bit block in column major order

    //generate key schedule in advance
   	KeyScheduler key_sch(user_key, aes_version);
	std::vector<std::vector<uint8_t>> expanded_key = key_sch.get_expanded_key();

	std::vector<std::vector<uint8_t>> crypt_buffer(4);

	//read and arrange 16 byte chunks of data into matrixes
    // char block[16];

    while(raw_file.good()){//edit

        char buff[util::CHBUF_SIZ];

        raw_file.read(buff, util::CHBUF_SIZ);
        // raw_file.read(block, 16);

        int bytes_read = raw_file.gcount();

        char state[4][4];
        int ctr = 0;

        while(ctr < bytes_read){

            std::pair<int, int> row_col_pair;

            int rem = bytes_read - ctr;

            if(rem >= 16){
                char* beg = &buff[ctr];
                char* end = &buff[ctr + 15];
                ctr += 16;

                row_col_pair = populate_state(state, beg, end, 16);
            }else if(rem > 0 && rem < 16){

                char* beg = &buff[ctr];
                char* end = &buff[ctr + rem];

                row_col_pair = populate_state(state, beg, end, rem);

                //fill state with block
                pad_pkcs_7(
                    state, row_col_pair.first,
                    row_col_pair.second, rem);
                ctr = bytes_read;//end

                // state test
                for(int row = 0; row < 4; row++){
                    std::cout <<"[";
                    for(int col = 0; col < 4; col++){
                        std::cout << state[row][col] <<", ";
                    }
                    std::cout << "]";
                    std::cout << "\n";
                }
            }else{
                break;
            }




             // start encryption
            int round_ctr = 0;
            int k_end_pos = 0;//(key end position) is incremented by 4

            for(int round = 0; round <= num_rounds; round++){

                if(round == 0){//first round
                    add_round_key(state, expanded_key, k_end_pos);

                    continue;
                }else if(round == num_rounds){//last round
                    sub_bytes(state);
                    shift_rows(state);
                    add_round_key(state, expanded_key, k_end_pos);

                    break;
                }else{
                    sub_bytes(state);
                    shift_rows(state);

                    uint8_t mix_state[4][4];// holds state after mix_column op

                    int col = 0;
                    int row = 0;

                    for(int st_col = 0; st_col < 4; st_col++){
                            for(int gf_row = 0; gf_row < 4; gf_row++){
                                uint8_t res = 0x00; //result

                                for(int gf_col = 0; gf_col < 4; gf_col++){

                                    int st_row = gf_col;

                                    res = res ^ mix_col(galois_field[gf_row][gf_col], state[st_row][st_col]);
                                }

                                mix_state[row][col] = res;

                                if(row == 3){
                                    row = 0;
                                    col++;
                                }else{
                                    row++;
                                }
                            }
                    }

                    for(int row = 0; row < 4; row++){//return mix col result back to state
                        for(int col = 0; col < 4; col++){
                            state[row][col] = mix_state[row][col];
                        }
                    }

                    add_round_key(state, expanded_key, k_end_pos);
                }
        }


        }

        push_to_buffer(state, crypt_buffer);

        int buffer_size = crypt_buffer.size() * crypt_buffer[0].size();

        if(buffer_size == util::CHBUF_SIZ){//flush buffer if full
            util::flush_buffer(crypt_buffer, encr_file);
        }

}


    if(!crypt_buffer.empty()){
        util::flush_buffer(crypt_buffer, encr_file);//flush buffer one final time to clear reminants
    }

    raw_file.close();
    encr_file.close();

}



uint8_t AesEncryption::mix_col(uint8_t field_val, uint8_t state_val){
    //g(2^3) == 8
        if(field_val == 0x01){//multiplying by 1 nets you the same value
            return state_val;
        }

        std::vector<int> field_non_z;
        std::vector<int> state_non_z;

        std::uint8_t mask = 0x80; //10000000

        //use mask to check if each bit is set in both values
        for(int i = 7; i >= 0; i--){

            uint8_t field_op = field_val | mask;
            uint8_t state_op = state_val | mask;

            if(field_val == field_op){
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

void AesEncryption::shift_rows(char state[4][4]){
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

//here
void AesEncryption::add_round_key(char mix_state[4][4], const std::vector<std::vector<uint8_t>> &expanded_key, int &k_end_pos){

    for(int row = 0; row < 4; row++){
        for(int col = 0; col < 4; col++){
            mix_state[row][col] =
                mix_state[row][col] ^ expanded_key[row][k_end_pos + col];
        }
    }

    k_end_pos += 4;
}

void AesEncryption::sub_bytes(char state[4][4]){

    for(int row = 0; row < 4; row++){
        for(int col = 0; col < 4; col++){
            std::pair<uint8_t, uint8_t> row_col_pair = util::separate(state[row][col]);
            //populate state with sbox mapped values
            state[row][col] = util::s_box[row_col_pair.first][row_col_pair.second];
        }
    }
}

void AesEncryption::push_to_buffer(char state[4][4], std::vector<std::vector<uint8_t>> &buffer){
    for(int col = 0; col < 4; col++){

        for(int row = 0; row < 4; row++){
            buffer[row].push_back(state[row][col]);
        }
    }
}

std::pair<int, int> AesEncryption::populate_state(char state[4][4], char *begin, char *end, int bytes_read){

    int last_col = 0;
    int last_row = 0;
    bool flag = false;

    for(int col = 0; col < 4; col++){
        for(int row = 0; row < 4; row++){

            if (flag == true) {
                last_col = col;
                last_row = row;
                break;
            }


            if(begin == end){//save stop position
                flag = true;
            }

            state[row][col] = *begin;

            begin++;
        }
    }

    return {last_row, last_col};
}


void AesEncryption::pad_pkcs_7(char state[4][4], int last_row_pos, int last_col_pos, int rem_bytes){
    for(int row = last_row_pos; row < 4; row++){
        for(int col = last_col_pos; col < 4; col++){
            state[row][col] = rem_bytes;
        }
    }
}
