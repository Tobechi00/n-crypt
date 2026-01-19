#ifndef UTIL_H
#define UTIL_H

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace util{

    const extern int CHBUF_SIZ;
    const extern std::vector<std::vector<uint8_t>> s_box;
    const extern std::vector<uint8_t> r_constants;

    extern bool is_file_valid(std::string file_path);

    extern std::filesystem::path generate_out_path(std::string in_file_path);
    extern std::filesystem::path generate_out_path_decr(std::string in_file_path);

    extern void flush_buffer(std::vector<std::vector<uint8_t>> &buffer, std::ofstream &file);


    extern std::pair<uint8_t, uint8_t> separate(uint8_t val);
    extern uint8_t combine(uint8_t row, uint8_t col);
    extern void reset_state(uint8_t state[4][4]);

    extern std::pair<int, int> populate_state(uint8_t state[4][4], char *begin, char *end, int bytes_read);
    extern void push_to_buffer(uint8_t state[4][4], std::vector<std::vector<uint8_t>> &buffer);

    extern uint8_t g_mul(uint8_t a, uint8_t b);
}

#endif
