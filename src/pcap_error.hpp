#pragma once
#include <stdexcept>
#include "pcap_error.hpp"

class PcapError : public std::runtime_error
{
private:
    const int errorCode;

public:
    PcapError(std::string message, int code) : std::runtime_error(message), errorCode(code){};
    int code()
    {
        return errorCode;
    }
};
class PcapError;