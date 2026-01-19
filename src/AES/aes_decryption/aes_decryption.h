#ifndef AES_DECRYPTION_H
#define AES_DECRYPTION_H


#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>
class AesDecryption{

    public:
    AesDecryption(std::string file_path, std::string user_key);

    private:
    void inv_sub_bytes(uint8_t state[4][4], std::unordered_map<uint8_t, uint8_t> &sub_map);
    void inv_shift_rows(uint8_t state[4][4]);
    void inv_add_round_key(uint8_t state[4][4], const std::vector<std::vector<uint8_t>> &expanded_key, int &k_end_pos);

    void inv_mix_col(uint8_t state[4][4]);
    void gen_sub_bytes(std::unordered_map<uint8_t, uint8_t> &sub_map);
};

#endif
