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

#include "./DCTcpGenericServerApp.h"

#include "inet/applications/common/SocketTag_m.h"
#include "inet/applications/tcpapp/GenericAppMsg_m.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/ProtocolTag_m.h"
#include "inet/common/lifecycle/NodeStatus.h"
#include "inet/common/packet/Message.h"
#include "inet/common/packet/chunk/ByteCountChunk.h"
#include "inet/common/TimeTag_m.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/transportlayer/contract/tcp/TcpCommand_m.h"

using namespace inet;

Define_Module(DCTcpGenericServerApp);

simsignal_t DCTcpGenericServerApp::bytesRequestedSignal = registerSignal("bytesRequested");

void DCTcpGenericServerApp::initialize(int stage)
{
    cSimpleModule::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        delay = par("replyDelay");
        maxMsgDelay = 0;

        //statistics
        msgsRcvd = msgsSent = bytesRcvd = bytesSent = 0;

        WATCH(msgsRcvd);
        WATCH(msgsSent);
        WATCH(bytesRcvd);
        WATCH(bytesSent);
    }
    else if (stage == INITSTAGE_APPLICATION_LAYER) {
        const char *localAddress = par("localAddress");
        int localPort = par("localPort");
        socket.setOutputGate(gate("socketOut"));
        socket.bind(localAddress[0] ? L3AddressResolver().resolve(localAddress) : L3Address(), localPort);
        socket.listen();

        cModule *node = findContainingNode(this);
        NodeStatus *nodeStatus = node ? check_and_cast_nullable<NodeStatus *>(node->getSubmodule("status")) : nullptr;
        bool isOperational = (!nodeStatus) || nodeStatus->getState() == NodeStatus::UP;
        if (!isOperational)
            throw cRuntimeError("This module doesn't support starting in node DOWN state");
    }
}

void DCTcpGenericServerApp::sendOrSchedule(cMessage *msg, simtime_t delay)
{
    if (delay == 0) {
        sendBack(msg);
    }
    else {
        scheduleAt(simTime() + delay, msg);
    }
}

void DCTcpGenericServerApp::sendBack(cMessage *msg)
{
    Packet *packet = dynamic_cast<Packet *>(msg);

    if (packet) {
        msgsSent++;
        bytesSent += packet->getByteLength();
        emit(packetSentSignal, packet);

        EV_INFO << "sending \"" << packet->getName() << "\" to TCP, " << packet->getByteLength() << " bytes\n";
    }
    else {
        EV_INFO << "sending \"" << msg->getName() << "\" to TCP\n";
    }

    auto& tags = getTags(msg);
    tags.addTagIfAbsent<DispatchProtocolReq>()->setProtocol(&Protocol::tcp);
    send(msg, "socketOut");
}

void DCTcpGenericServerApp::handleMessage(cMessage *msg)
{
    EV << "SEPEHR: handleMessage called and msg is: " << msg << endl;
    if (msg->isSelfMessage()) {
        EV << "msg is a self msg" << endl;
        sendBack(msg);
    }
    else if (msg->getKind() == TCP_I_PEER_CLOSED) {
        // we'll close too, but only after there's surely no message
        // pending to be sent back in this connection
        int connId = check_and_cast<Indication *>(msg)->getTag<SocketInd>()->getSocketId();
        delete msg;
        auto request = new Request("close", TCP_C_CLOSE);
        request->addTag<SocketReq>()->setSocketId(connId);
        EV << "Peer closed itself and sent FIN. Closing after " << maxMsgDelay << "s" << endl;
        sendOrSchedule(request, maxMsgDelay);
    }
    else if (msg->getKind() == TCP_I_DATA || msg->getKind() == TCP_I_URGENT_DATA) {
        Packet *packet = check_and_cast<Packet *>(msg);
        EV << "SEPEHR: packet received " << packet << endl;
        unsigned long requester_id;
        simtime_t requested_time;
        bool is_micro_burst_flow;
        unsigned long query_id;
        int connId = packet->getTag<SocketInd>()->getSocketId();
        ChunkQueue &queue = socketQueue[connId];
        auto chunk = packet->peekDataAt(B(0), packet->getTotalLength());
        queue.push(chunk);
        emit(packetReceivedSignal, packet);
        EV << "SEPEHR: queue length is: " << queue.getLength() << endl;
        bool doClose = false;
        auto mchunk = queue.pop<SliceChunk>(b(-1), Chunk::PF_ALLOW_NULLPTR + Chunk::PF_ALLOW_INCOMPLETE);
        while (mchunk) {
            EV << "SEPEHR: chunk is: " << mchunk << endl;
            auto main_chunk = mchunk->getChunk();
            if(mchunk->getLength() + mchunk->getOffset() == main_chunk->getChunkLength()){
                EV << "Request is thoroughly received, lets send the response" << endl;
                Packet* temp = new Packet();
                temp->insertAtBack(main_chunk);
                auto appmsg = temp->popAtFront<GenericAppMsg>();
                EV << "SEPEHR: appmsg is " << appmsg << endl;
                requester_id = appmsg->getRequesterID();
                requested_time = appmsg->getRequested_time();
                is_micro_burst_flow = appmsg->getIs_micro_burst_flow();
                if (is_micro_burst_flow)
                    query_id = appmsg->getQuery_id();
                delete temp;
                msgsRcvd++;
                bytesRcvd += B(appmsg->getChunkLength()).get();
                B requestedBytes = appmsg->getExpectedReplyLength();
                EV << "SEPEHR: requested bytes is: " << requestedBytes << endl;
                simtime_t msgDelay = appmsg->getReplyDelay();
                if (msgDelay > maxMsgDelay)
                    maxMsgDelay = msgDelay;

                if (requestedBytes > B(0)) {
                    Packet *outPacket = new Packet(msg->getName(), TCP_C_SEND);
                    outPacket->addTag<SocketReq>()->setSocketId(connId);
                    const auto& payload = makeShared<GenericAppMsg>();
                    payload->setChunkLength(requestedBytes);
                    payload->setExpectedReplyLength(B(0));
                    payload->setReplyDelay(0);
                    payload->setIs_micro_burst_flow(is_micro_burst_flow);
                    if (is_micro_burst_flow)
                        payload->setQuery_id(query_id);
                    EV << "SEPEHR: setting requester id for the reply. Requester ID is: " << requester_id << endl;
                    payload->setRequesterID(requester_id);
                    payload->setRequested_time(requested_time);
                    payload->addTag<CreationTimeTag>()->setCreationTime(simTime());
                    outPacket->insertAtBack(payload);
                    emit(DCTcpGenericServerApp::bytesRequestedSignal, requestedBytes.get());
                    sendOrSchedule(outPacket, delay + msgDelay);
                }
                if (appmsg->getServerClose()) {
                    doClose = true;
                    break;
                }
            } else {
                EV << "This is not a complete request, keep waiting to receive all of it!" << endl;
            }
            mchunk = queue.pop<SliceChunk>(b(-1), Chunk::PF_ALLOW_NULLPTR + Chunk::PF_ALLOW_INCOMPLETE);
        }
        delete msg;

        if (doClose) {
            auto request = new Request("close", TCP_C_CLOSE);
            TcpCommand *cmd = new TcpCommand();
            request->addTag<SocketReq>()->setSocketId(connId);
            request->setControlInfo(cmd);
            EV << "The other application set ServerClose to True. Closing after " << maxMsgDelay << "s" << endl;
            sendOrSchedule(request, maxMsgDelay);
        }

    }
    else if (msg->getKind() == TCP_I_AVAILABLE)
        socket.processMessage(msg);
    else {
        // some indication -- ignore
        EV_WARN << "drop msg: " << msg->getName() << ", kind:" << msg->getKind() << "(" << cEnum::get("inet::TcpStatusInd")->getStringFor(msg->getKind()) << ")\n";
        delete msg;
    }
}

void DCTcpGenericServerApp::refreshDisplay() const
{
    char buf[64];
    sprintf(buf, "rcvd: %ld pks %ld bytes\nsent: %ld pks %ld bytes", msgsRcvd, bytesRcvd, msgsSent, bytesSent);
    getDisplayString().setTagArg("t", 0, buf);
}

void DCTcpGenericServerApp::finish()
{
    EV_INFO << getFullPath() << ": sent " << bytesSent << " bytes in " << msgsSent << " packets\n";
    EV_INFO << getFullPath() << ": received " << bytesRcvd << " bytes in " << msgsRcvd << " packets\n";
}


