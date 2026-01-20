#ifndef AES_ENCRYPTION_H
#define AES_ENCRYPTION_H

#include <cstdint>
#include <string>
#include <sys/types.h>
#include <vector>
class AesEncryption{

    public:
    AesEncryption(std::string file_path, std::string user_key);

    private:
    void mix_col(uint8_t state[4][4]);

    void shift_rows(uint8_t state[4][4]);

    uint8_t rot_word(uint8_t val);

    void add_round_key(uint8_t arr[4][4], const std::vector<std::vector<uint8_t>> &expanded_key, int &k_end_pos);

    void sub_bytes(uint8_t state[4][4]);

    //ISO/IEC 7816-4
    void pad_iso(uint8_t state[4][4], int last_row_pos, int last_col_pos);

};

#endif
