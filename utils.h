// utils.h
#pragma once

#include <vector>
#include <string>
#include <fstream>
#include <iterator>
#include <stdexcept>

using bytes = std::vector<unsigned char>;

inline bytes read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot open file: " + path);
    return bytes((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

inline void write_file(const std::string& path, const bytes& data) {
    std::ofstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot write file: " + path);
    f.write(reinterpret_cast<const char*>(data.data()), data.size());
}

inline bool ends_with(const std::string& str, const std::string& suffix) {
    return suffix.size() <= str.size() &&
        str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}