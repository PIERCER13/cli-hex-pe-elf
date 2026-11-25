// @author piercer
#include <cmath>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

static double shannonEntropy(const uint8_t* data, size_t len) {
    if (len == 0) return 0.0;
    size_t freq[256] = {0};
    for (size_t i = 0; i < len; ++i) freq[data[i]]++;
    double ent = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (freq[i] == 0) continue;
        double p = static_cast<double>(freq[i]) / static_cast<double>(len);
        ent -= p * std::log2(p);
    }
    return ent;
}

static uint16_t readU16(const std::vector<uint8_t>& b, size_t off) {
    return static_cast<uint16_t>(b[off] | (b[off + 1] << 8));
}

static uint32_t readU32(const std::vector<uint8_t>& b, size_t off) {
    return static_cast<uint32_t>(b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24));
}

static void printHexDump(const std::vector<uint8_t>& b, size_t maxBytes) {
    size_t lim = std::min(b.size(), maxBytes);
    for (size_t i = 0; i < lim; i += 16) {
        std::cout << std::hex << std::setw(8) << std::setfill('0') << i << "  ";
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < lim) std::cout << std::setw(2) << static_cast<int>(b[i + j]) << " ";
            else std::cout << "   ";
        }
        std::cout << " |";
        for (size_t j = 0; j < 16 && i + j < lim; ++j) {
            uint8_t c = b[i + j];
            std::cout << (c >= 32 && c <= 126 ? static_cast<char>(c) : '.');
        }
        std::cout << "|\n";
    }
    std::cout << std::dec;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Uso: piercer_cli_hex <arquivo> [--hex]\n";
        return 1;
    }
    std::ifstream f(argv[1], std::ios::binary);
    if (!f) {
        std::cerr << "Erro ao abrir arquivo: " << argv[1] << "\n";
        return 1;
    }
    std::vector<uint8_t> buf((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    std::cout << "=== Piercer CLI Hex / PE / ELF Inspector ===\n";
    std::cout << "Arquivo : " << argv[1] << " (" << buf.size() << " bytes)\n";
    std::cout << "Entropia: " << std::fixed << std::setprecision(3) << shannonEntropy(buf.data(), buf.size()) << "\n";

    if (buf.size() >= 64 && readU16(buf, 0) == 0x5A4D) {
        uint32_t lf = readU32(buf, 0x3C);
        if (lf + 24 < buf.size() && readU32(buf, lf) == 0x00004550) {
            uint16_t numSec = readU16(buf, lf + 6);
            uint16_t optSize = readU16(buf, lf + 20);
            uint16_t magic = readU16(buf, lf + 24);
            std::cout << "Formato : PE (" << (magic == 0x20B ? "PE32+ x64" : "PE32 x86") << "), Secoes: " << numSec << "\n";
            size_t secOff = lf + 24 + optSize;
            for (uint16_t i = 0; i < numSec && secOff + 40 <= buf.size(); ++i, secOff += 40) {
                std::string name(reinterpret_cast<const char*>(&buf[secOff]), 8);
                name = name.c_str();
                uint32_t rsize = readU32(buf, secOff + 16);
                uint32_t ra = readU32(buf, secOff + 20);
                size_t avail = ra < buf.size() ? std::min<size_t>(rsize, buf.size() - ra) : 0;
                double ent = avail ? shannonEntropy(&buf[ra], avail) : 0.0;
                std::cout << "  [" << name << "] RawSize=" << rsize << " Entropy=" << std::setprecision(2) << ent << "\n";
            }
        }
    } else if (buf.size() >= 20 && buf[0] == 0x7F && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F') {
        std::cout << "Formato : ELF (" << (buf[4] == 2 ? "64-bit" : "32-bit") << ")\n";
    } else {
        std::cout << "Formato : Binario generico\n";
    }

    if (argc >= 3 && std::string(argv[2]) == "--hex") {
        std::cout << "\n--- Hex Dump (primeiros 256 bytes) ---\n";
        printHexDump(buf, 256);
    }
    return 0;
}
