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
    extern bool is_file_valid(std::string file_path);

    extern std::filesystem::path generate_out_path(std::string in_file_path);

    extern void flush_buffer(std::vector<std::vector<uint8_t>> buffer, std::ofstream &file);


    extern std::pair<uint8_t, uint8_t> separate(uint8_t val);
}

#endif
