//
// Copyright (C) 2004 Andras Varga
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//

#include "MultiSocketTcpAppBase.h"

#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/transportlayer/contract/tcp/TcpSocket.h"
#include "inet/applications/common/SocketTag_m.h"

using namespace inet;

simsignal_t MultiSocketTcpAppBase::connectSignal = registerSignal("connect");

MultiSocketTcpAppBase::~MultiSocketTcpAppBase() {
    for (auto socket_pair: socket_map.getMap())
        delete socket_pair.second;
}

void MultiSocketTcpAppBase::initialize(int stage)
{
    ApplicationBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        numSessions = numBroken = packetsSent = packetsRcvd = bytesSent = bytesRcvd = 0;

        WATCH(numSessions);
        WATCH(numBroken);
        WATCH(packetsSent);
        WATCH(packetsRcvd);
        WATCH(bytesSent);
        WATCH(bytesRcvd);


    }
}

void MultiSocketTcpAppBase::handleMessageWhenUp(cMessage *msg)
{
    EV << "SEPEHR: Handling Message wMultiSocketTcpAppBaseTcpAppBase! msg is: " << msg->str() << endl;
    if (msg->isSelfMessage()) {
        EV << "SEPEHR: Calling handleTimer" << endl;
        handleTimer(msg);
    }

    else {
        EV << "SEPEHR: Calling socket.processMessage" << endl;

        TcpSocket *socket = check_and_cast_nullable<TcpSocket*>(socket_map.findSocketFor(msg));
        if (socket) {
            socket->processMessage(msg);
            return;
        }

        throw cRuntimeError("message %s(%s) arrived for unknown socket 1\n", msg->getFullName(), msg->getClassName());
        delete msg;
    }
}

void MultiSocketTcpAppBase::connect(int local_port, int dest_server_idx, int connect_port, bool is_bursty,
        unsigned long query_id)
{
    TcpSocket* socket;
    bool found = false;
    bool is_server0 = getParentModule()->getIndex() == 0;
    for (auto socket_pair: socket_map.getMap()) {
        socket = check_and_cast_nullable<TcpSocket*>(socket_pair.second);
        if (!socket->isOpen()) {
            if (is_server0)
                EV << "SEPEHR: found an idle socket for server " << dest_server_idx << " so there is no need to initiate one." << endl;
            found = true;
            socket_map.removeSocket(socket);
            if (is_server0)
                EV << "SEPEHR: sockets old id is: " << socket->getSocketId();
            socket->renewSocket();
            if (is_server0)
                EV << " and it's revived id is " << socket->getSocketId() << endl;
            break;
        }
    }

    if (!found) {
        socket = new TcpSocket();
    }
    const char *localAddress = par("localAddress");
    socket->bind(*localAddress ? L3AddressResolver().resolve(localAddress) : L3Address(), local_port);
    socket->setCallback(this);
    socket->setOutputGate(gate("socketOut"));

    std::string connect_address_str = "server[" + std::to_string(dest_server_idx) + "]";
    const char* connect_address = connect_address_str.c_str();
    int timeToLive = par("timeToLive");
    if (timeToLive != -1)
        socket->setTimeToLive(timeToLive);

    int dscp = par("dscp");
    if (dscp != -1)
        socket->setDscp(dscp);

    // connect
    L3Address destination;
    L3AddressResolver().tryResolve(connect_address, destination);
    if (destination.isUnspecified()) {
        throw cRuntimeError("Connecting to %a port= %s: cannot resolve destination address\n", connect_address, connect_port);
    }
    else {
        EV_INFO << "Connecting to " << connect_address << "(" << destination << ") port=" << connect_port << endl;
        socket->connect(destination, connect_port);
        numSessions++;
//        emit(connectSignal, 1L);
    }
    if (is_server0)
        EV << "SEPEHR: adding socket with id: " << socket->getSocketId() <<
                " to the list for server " << dest_server_idx << ". Before adding the size of socket_map is "
                << socket_map.size();
    socket_map.addSocket(socket);
    if (is_server0)
        EV << ". after adding it's size is " << socket_map.size() << endl;

    // store the socket if the flow is bursty
    if (is_bursty)
        socket_query_mapper.insert(std::pair<TcpSocket*, unsigned long>(socket, query_id));

}

unsigned long MultiSocketTcpAppBase::get_query_id_for_socket(Packet *msg) {
    TcpSocket *socket = check_and_cast_nullable<TcpSocket*>(socket_map.findSocketFor(msg));
    if (!socket)
        throw cRuntimeError("How is the socket not found!");
    auto query_id_found = socket_query_mapper.find(socket);
    if (query_id_found == socket_query_mapper.end())
        throw cRuntimeError("How is the query ID not found!");
    unsigned long query_id = query_id_found->second;
    socket_query_mapper.erase(query_id_found->first);
    return query_id;
}

void MultiSocketTcpAppBase::socketEstablished(TcpSocket *)
{
    // *redefine* to perform or schedule first sending
    EV_INFO << "connected\n";
}

void MultiSocketTcpAppBase::close(int socket_id)
{
    EV_INFO << "issuing CLOSE command\n";

    TcpSocket *socket = check_and_cast_nullable<TcpSocket*>(socket_map.getSocketById(socket_id));
    if (socket) {
        socket->close();
        return;
    }

    throw cRuntimeError("No socket was found for socket id %d", socket_id);
}

void MultiSocketTcpAppBase::sendPacket(Packet *msg)
{
    TcpSocket *socket = check_and_cast_nullable<TcpSocket*>(socket_map.findSocketFor(msg));
    if (socket) {
        delete msg->removeTagIfPresent<SocketInd>();
        EV << "SEPEHR: the packet is related to a socket with id " << socket->getSocketId() << endl;
        int numBytes = msg->getByteLength();
        emit(packetSentSignal, msg);
        socket->send(msg);

        packetsSent++;
        bytesSent += numBytes;
        return;
    }

    throw cRuntimeError("message %s(%s) arrived for unknown socket 2\n", msg->getFullName(), msg->getClassName());    delete msg;

}

void MultiSocketTcpAppBase::refreshDisplay() const
{
    ApplicationBase::refreshDisplay();
//    getDisplayString().setTagArg("t", 0, TcpSocket::stateName(socket.getState()));
}

void MultiSocketTcpAppBase::socketDataArrived(TcpSocket *, Packet *msg, bool)
{
    // *redefine* to perform or schedule next sending
    packetsRcvd++;
    bytesRcvd += msg->getByteLength();\
    EV << "Emitting packetReceivedSignal with msg: " << msg << endl;
    emit(packetReceivedSignal, msg);
    delete msg;
}

void MultiSocketTcpAppBase::socketPeerClosed(TcpSocket *socket_)
{
//    ASSERT(socket_ == &socket);
    // close the connection (if not already closed)
//    if (socket.getState() == TcpSocket::PEER_CLOSED) {
//        EV_INFO << "remote TCP closed, closing here as well\n";
//        close();
//    }
}

void MultiSocketTcpAppBase::socketClosed(TcpSocket *)
{
    // *redefine* to start another session etc.
    EV_INFO << "connection closed\n";
}

void MultiSocketTcpAppBase::socketFailure(TcpSocket *, int code)
{
    // subclasses may override this function, and add code try to reconnect after a delay.
    EV_WARN << "connection broken\n";
    numBroken++;
}

void MultiSocketTcpAppBase::finish()
{
    std::string modulePath = getFullPath();

    EV_INFO << modulePath << ": opened " << numSessions << " sessions\n";
    EV_INFO << modulePath << ": sent " << bytesSent << " bytes in " << packetsSent << " packets\n";
    EV_INFO << modulePath << ": received " << bytesRcvd << " bytes in " << packetsRcvd << " packets\n";
}

