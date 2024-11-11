#pragma once
#include <string>
#include <sstream>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <vector>

namespace utils {
    template<typename T>
    std::string join(T *array, int size, const std::string delimiter = " ");
    std::string macToString(const uint8_t mac[6], const std::string delimiter = ":");
    std::string sniToString(const uint8_t *sni, uint16_t length);
}
