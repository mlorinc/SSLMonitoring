#include "utils.hpp"
#include <iomanip>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <cstring>
#include <arpa/inet.h>

namespace utils
{
    template <typename T>
    std::string join(T array[], int size, const std::string delimiter)
    {
        if (size == 0)
        {
            return "";
        }

        if (size < 0)
        {
            throw std::invalid_argument("Size cannot be negative");
        }

        std::ostringstream sb;
        for (int i = 0; i < size - 1; i++)
        {
            sb << array[i] << delimiter;
        }
        sb << array[size - 1];
        return sb.str();
    }

    template <>
    std::string join(uint8_t array[], int size, const std::string delimiter)
    {
        if (size == 0)
        {
            return "";
        }

        if (size < 0)
        {
            throw std::invalid_argument("Size cannot be negative");
        }

        std::ostringstream sb;
        for (int i = 0; i < size - 1; i++)
        {
            sb << std::setfill('0') << std::setw(2) << std::right << std::hex << (int)array[i] << delimiter;
        }
        sb << std::setfill('0') << std::setw(2) << std::right << std::hex << (int)array[size - 1];
        return sb.str();
    }

    std::string macToString(const uint8_t mac[6], const std::string delimiter)
    {
        std::ostringstream sb;
        for (int i = 0; i < 5; i++)
        {
            sb << std::setfill('0') << std::setw(2) << std::right << std::hex << (int)mac[i] << delimiter;
        }
        sb << std::setfill('0') << std::setw(2) << std::right << std::hex << (int)mac[5];
        return sb.str();
    }

    std::string sniToString(const uint8_t *sni, uint16_t length)
    {
        return std::string(reinterpret_cast<const char *>(sni), length);
    }
} // namespace utils