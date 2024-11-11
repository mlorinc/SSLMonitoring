#include <iostream>
#include <string>
#include <exception>
#include <pcap.h>
#include <unistd.h>
#include <ctime>
#include <memory>
#include "packet.hpp"
#include "pcap_wrapper.hpp"
#include "pcap_error.hpp"
#include "utils.hpp"
#include "tls.hpp"
#include "session_manager.hpp"

struct ProgramArguments
{
    std::string file;
    std::string interface;
};

constexpr int BUFFER_SIZE = 4096;
std::unique_ptr<tcp::SessionManager> sessionManager;

struct ProgramArguments parseArguments(int argc, char *const *argv)
{
    struct ProgramArguments args = {"", ""};

    int option = 0;
    while ((option = getopt(argc, argv, "i:r:")) != -1)
    {
        switch (option)
        {
        case 'i':
            args.interface = optarg;
            break;
        case 'r':
            args.file = optarg;
            break;
        case '?':
            if (optopt == 'i' || optopt == 'r')
            {
                throw std::invalid_argument(std::string("Option ") + std::to_string(optopt) + std::string(" requires an argument."));
            }
            else
            {
                throw std::invalid_argument(std::string("Unknown option ") + std::to_string(optopt));
            };
        default:
            throw std::invalid_argument(std::string("Parser error: ") + std::to_string(option));
        }
    }

    return args;
}

void handleSession(const tcp::Session &session)
{
    try
    {
        auto sni = session.getSNI();

        if (sni.empty())
        {
            return;
        }

        std::cout << session.getTimestamp() << "," << session.getSourceAddress() << "," << session.getSourcePort() << ","
                  << session.getDestinationAddress() << "," << sni << "," << session.getTlsPayloadLength()
                  << "," << session.getPacketsCount() << "," << session.getDuration() << std::endl;
    }
    catch (std::exception &e)
    {
        // std::cerr << e.what() << std::endl;
    }
}

void handlePacket(u_char *args, const struct pcap_pkthdr *header,
                  const u_char *packet)
{
    (void)args;
    try
    {
        auto packetWrapper = std::shared_ptr<Packet>(new Packet(packet, *header));
        sessionManager->add(packetWrapper);

        for (auto session : sessionManager->getCompletedSessions())
        {
            handleSession(*session);
        }
        sessionManager->destroyCompletedSessions();
    }
    catch (tls::TlsPayloadError &e)
    {
        char buffer[64] = {0};
        std::strftime(buffer, 64, "%Y-%m-%d %H:%M:%S", std::localtime(&(header->ts.tv_sec)));
        std::cerr << buffer << "." << header->ts.tv_usec << ": " << e.what() << std::endl;
    }
    catch (std::exception &e)
    {
        std::cerr << e.what() << std::endl;
    }
}

int main(int argc, char *const *argv)
{
    try
    {
        auto args = parseArguments(argc, argv);
        if (args.interface.empty() && args.file.empty())
        {
            std::cout << "SSL packet sniffer tool" << std::endl;
            std::cout << "Usage: sslsniff [-r <file>] [-i interface]" << std::endl;
            return 0;
        }

        std::string arg;
        PcapMode mode;

        if (args.interface.empty())
        {
            arg = args.file;
            mode = PcapMode::OFFLINE;
        }
        else
        {
            arg = args.interface;
            mode = PcapMode::LIVE;
        }

        auto pcap = PcapWrapper(arg, mode);
        pcap.setFilter("tcp", false);

        sessionManager = std::unique_ptr<tcp::SessionManager>(new tcp::SessionManager(5000));
        int loopResult = pcap.startLoop(handlePacket);

        while (!sessionManager->isPacketQueueEmpty())
        {
            auto count = sessionManager->tryAddFromPacketQueue();
            if (mode == PcapMode::OFFLINE && count == 0)
            {
                break;
            }

            for (auto session : sessionManager->getCompletedSessions())
            {
                handleSession(*session);
            }
            sessionManager->destroyCompletedSessions();
        }

        for (auto session : sessionManager->getSessions()) {
            handleSession(*session);
        }

        return loopResult == 0 || loopResult == PCAP_ERROR_BREAK ? 0 : loopResult;
    }
    catch (PcapError &e)
    {
        std::cerr << e.what() << std::endl;
        return e.code();
    }
    catch (std::exception &e)
    {
        std::cerr << e.what() << std::endl;
        return 1;
    }
}
