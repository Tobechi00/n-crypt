#ifndef UTIL_H
#define UTIL_H

#include <cstdint>
#include <vector>

namespace util{

    const extern int CHBUF_SIZ;
    const extern std::vector<std::vector<uint8_t>> s_box;


    extern std::pair<uint8_t, uint8_t> separate(uint8_t val);
}

#endif
