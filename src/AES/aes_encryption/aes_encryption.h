#ifndef AES_ENCRYPTION_H
#define AES_ENCRYPTION_H

#include <cstdint>
#include <string>
#include <sys/types.h>
#include <vector>
class AesEncryption{

    static const std::vector<int> poly_rs_8;//4
    static const std::vector<std::vector<uint8_t>> galois_field;//4x4

    public:
    AesEncryption(std::string file_path, std::string user_key);

    private:
    uint8_t mix_col(uint8_t field_val, uint8_t state_val);

    void shift_rows(char state[4][4]);

    uint8_t rot_word(uint8_t val);

    void add_round_key(char arr[4][4], const std::vector<std::vector<uint8_t>> &expanded_key, int &k_end_pos);

    void sub_bytes(char state[4][4]);

    void push_to_buffer(char state[4][4], std::vector<std::vector<uint8_t>> &buffer);

    std::pair<int, int> populate_state(char state[4][4], char *begin, char *end, int bytes_read);

    void pad_pkcs_7(char state[4][4], int last_row_pos, int last_col_pos, int rem_bytes);

};

#endif
