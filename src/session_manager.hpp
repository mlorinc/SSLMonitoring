#pragma once
#include <memory>
#include "session.hpp"

namespace tcp
{
    class SessionManager
    {
    public:
        /**
         * Create new session manager with timeout. Timeout is used to determine if packet should be discarded.
         */ 
        SessionManager(int timeoutSeconds);
        ~SessionManager();
        /**
         * Add packet to session manager
         */ 
        void add(std::shared_ptr<Packet> packet);

        /**
         * Atttempt to add packets to existing sessions or create new sessions
         */ 
        size_t tryAddFromPacketQueue();
        bool isPacketQueueEmpty() const;
        /**
         * Remove session from manager
         */ 
        void removeSession(const Session &session);

        /**
         * Get properly finished sessions
         */ 
        std::list<std::shared_ptr<Session>> getCompletedSessions();

        /**
         * Get all existing sessions
         */ 
        std::list<std::shared_ptr<Session>> getSessions() const;

        /**
         * Remove completed sessions
         */ 
        void destroyCompletedSessions();
    private:
        std::list<std::shared_ptr<Packet>> packetQueue;
        std::list<std::shared_ptr<Session>> completedSessions;
        std::map<std::string, std::shared_ptr<Session>> sessions;
        void createSession(std::shared_ptr<Packet> synPacket);
        std::list<std::shared_ptr<Packet>>::iterator nextPacket(std::list<std::shared_ptr<Packet>>::iterator it);
        const int timeoutSeconds;
    };
} // namespace tcp
