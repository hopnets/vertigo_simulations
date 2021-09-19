//
// Copyright (C) OpenSim Ltd.
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
// along with this program; if not, see http://www.gnu.org/licenses/.
//

#ifndef __INET_DCTCPREDDROPPER_H
#define __INET_DCTCPREDDROPPER_H

#include "inet/common/packet/Packet.h"
#include "inet/queueing/base/PacketFilterBase.h"
#include "inet/queueing/contract/IPacketCollection.h"

namespace inet {
namespace queueing {

/**
 * Implementation of Random Early Detection (RED).
 */
class INET_API DCTCPRedDropper : public PacketFilterBase
{
  protected:
    double wq = 0.0;
    double minth = NaN;
    double maxth = NaN;
    double maxp = NaN;
    double pkrate = NaN;
    double count = NaN;

    double avg = 0.0;
    simtime_t q_time;

    int packetCapacity = -1;
    b dataCapacity = b(-1);
    int threshold = -1;
    bool useEcn = false;
    bool markNext = false;

    static simsignal_t queueCapSignal;

    IPacketCollection *collection = nullptr;

    enum RedResult { QUEUE_FULL, ABOVE_THRESHOLD, BELOW_THRESHOLD };

  protected:
    virtual void initialize(int stage) override;
    virtual RedResult doRandomEarlyDetection(Packet *packet);
    virtual bool matchesPacket(Packet *packet) override;
    virtual void pushOrSendPacket(Packet *packet, cGate *gate, IPassivePacketSink *consumer) override;
};

} // namespace queueing
} // namespace inet

#endif // ifndef __INET_DCTCPREDDROPPER_H
