#include "session_manager.hpp"
#include <iostream>
#include <stdexcept>

namespace tcp
{
    SessionManager::SessionManager(int timeoutSeconds): timeoutSeconds(timeoutSeconds)
    {
    }

    SessionManager::~SessionManager() {

    }

    void SessionManager::add(std::shared_ptr<Packet> packet)
    {
        packetQueue.push_front(packet);
        tryAddFromPacketQueue();
    }

    std::list<std::shared_ptr<Packet>>::iterator SessionManager::nextPacket(std::list<std::shared_ptr<Packet>>::iterator it) {
        auto recent = packetQueue.front();
        if (recent->getPcapHeader().ts.tv_sec - (*it)->getPcapHeader().ts.tv_sec > timeoutSeconds)
        {
            return packetQueue.erase(it);
        }
        return ++it;
    }

    size_t SessionManager::tryAddFromPacketQueue()
    {
        size_t processedCount = 0;
        auto end = packetQueue.end();
        for (auto it = packetQueue.begin(); it != end;)
        {
            auto packet = *it;
            auto tcp = packet->getTcpPacket();
            try
            {
                if (tcp->syn == 1 && tcp->ack == 0)
                {
                    createSession(packet);
                    it = packetQueue.erase(it);
                    processedCount++;
                    continue;
                }
            }
            catch (std::runtime_error &e)
            {
                // std::cerr << e.what() << std::endl;
                it = nextPacket(it);
                continue;
            }

            auto id = packet->getSessionId();
            auto session = sessions.find(id.toString());

            // if session is not found try flip source and destination
            if (session == sessions.end())
            {
                id.flip();
                session = sessions.find(id.toString());
            }

            try
            {
                if (session != sessions.end() && session->second->add(packet))
                {
                    it = packetQueue.erase(it);
                    processedCount++;

                    if (session->second->isClosed())
                    {
                        completedSessions.push_back(session->second);
                    }
                }
                else
                {
                    it = nextPacket(it);
                }
            }
            catch (tcp::OutOfOrderPacket &e)
            {
                // std::cerr << e.what() << std::endl;
                it = nextPacket(it);
                // it = packetQueue.erase(it);
                // processedCount++;
                // if (session->second->isClosed())
                // {
                //     completedSessions.push_back(session->second);
                // }
            }
        }
        return processedCount;
    }

    bool SessionManager::isPacketQueueEmpty() const
    {
        return packetQueue.empty();
    }

    void SessionManager::createSession(std::shared_ptr<Packet> synPacket)
    {
        auto tcp = synPacket->getTcpPacket();
        if (tcp->syn != 1 || tcp->ack == 1)
        {
            throw std::runtime_error("This is not sync packet.");
        }
        auto id = synPacket->getSessionId();

        auto s = sessions.find(id.toString());
        if (s != sessions.end())
        {
            throw std::runtime_error(
                "Session already exists: " + s->second->getSourceAddress() + ":" + std::to_string(s->second->getSourcePort()) + " => " + s->second->getDestinationAddress() + ":" + std::to_string(s->second->getDestinationPort()));
        }
        std::shared_ptr<Session> session(new Session(synPacket));

        // std::cerr << "Created " << session->getSourceAddress() << ":" << session->getSourcePort() << " => "
        //           << session->getDestinationAddress() << ":" << session->getDestinationPort() << std::endl;
        sessions.insert({id.toString(), std::move(session)});
    }

    void SessionManager::removeSession(const Session &session)
    {
        auto id = session.getSessionId();
        if (sessions.erase(session.getSessionId().toString()) == 0)
        {
            throw std::runtime_error(
                "Could not destroy: " + session.getSourceAddress() + ":" + std::to_string(session.getSourcePort()) + " => " + session.getDestinationAddress() + ":" + std::to_string(session.getDestinationPort()));
        }

        // auto end = packetQueue.end();
        // for (auto it = packetQueue.begin(); it != end;)
        // {
        //     auto packet = *it;
        //     auto packetId = packet->getSessionId();

        //     // if session is not found try flip source and destination
        //     if (packetId == id)
        //     {
        //         it = packetQueue.erase(it);
        //         continue;
        //     }
        //     else
        //     {
        //         packetId.flip();
        //     }

        //     if (packetId == id)
        //     {
        //         it = packetQueue.erase(it);
        //         continue;
        //     }
        //     else
        //     {
        //         it++;
        //     }
        // }
    }

    std::list<std::shared_ptr<Session>> SessionManager::getCompletedSessions()
    {
        return completedSessions;
    }

    void SessionManager::destroyCompletedSessions()
    {
        for (auto session : completedSessions)
        {
            // std::cerr << "Destroying " << session->getSourceAddress() << ":" << std::to_string(session->getSourcePort()) << " => "
            //           << session->getDestinationAddress() << ":" << std::to_string(session->getDestinationPort()) << std::endl;
            removeSession(*session);
        }
        completedSessions.clear();
    }

    std::list<std::shared_ptr<Session>> SessionManager::getSessions() const {
        std::list<std::shared_ptr<Session>> out;
        for (auto pair : sessions) {
            out.push_back(pair.second);
        }
        return out;
    }
} // namespace tcp
