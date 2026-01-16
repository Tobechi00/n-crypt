#ifndef AES_DECRYPTION_H
#define AES_DECRYPTION_H


#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>
class AesDecryption{

    static const std::vector<std::vector<uint8_t>> inv_mix_col_mat;
    static const std::vector<int> poly_rs_8;


    AesDecryption(std::string file_path, std::string user_key);

    void inv_sub_bytes(char state[4][4], std::unordered_map<uint8_t, uint8_t> &sub_map);
    void inv_shift_rows(char state[4][4]);
    uint8_t inv_mix_col(uint8_t inv_val, uint8_t state_val);
    void inv_add_round_key(char state[4][4], const std::vector<std::vector<uint8_t>> &expanded_key, int &k_end_pos);
    void gen_sub_bytes(std::unordered_map<uint8_t, uint8_t> &sub_map);
};

#endif
