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

#ifndef __INET_SWIFT_H
#define __INET_SWIFT_H

#include "inet/common/INETDefs.h"
#include "inet/transportlayer/tcp/flavours/SwiftFamily.h"


namespace inet {
namespace tcp {

/**
 * State variables for Swift.
 */
typedef SwiftFamilyStateVariables SwiftStateVariables;

/**
 * Implements TCP Reno.
 */
class INET_API Swift : public SwiftFamily
{
  protected:

    static simsignal_t fcwndSignal;
    static simsignal_t ecwndSignal;
    static simsignal_t pacingDelaySignal;
    static simsignal_t pacingTimerExpiredSignal;
    static simsignal_t pacingTimerSetSignal;

    SwiftStateVariables *& state;    // alias to TCLAlgorithm's 'state'

    simtime_t t_last_decrease = 0;       // fabric last time decrease happened
    double pacing_delay = 0;

    // endpoint stuff, In simulations, the endpoint delay is 0
    double ecwnd;   // endpoint cwnd
    simtime_t endpoint_target_delay;    // endpoint delay target

    // fabric stuff
    double fcwnd;   // fabric cwnd
    simtime_t fabric_target_delay;      // fabric target delay

    unsigned int retransmit_cnt = 0;
    simtime_t most_recent_rtt;
    simtime_t target_delay;

    /** Create and return a SwiftStateVariables object. */
    virtual TcpStateVariables *createStateVariables() override
    {
        return new SwiftStateVariables();
    }

  public:
    /** Ctor */
    Swift();

    /*
     * Calculate the final values of ecwnd and fcwnd and update the cwnd
     * accordingly
     */
    virtual void set_final_cwnd_values(simtime_t now, uint32 prev_ecwnd);

    /*
     * Calculates target delay for endpoint and fabric
     */
    virtual simtime_t calculate_target_delay(int type);

    virtual void initialize() override;
    virtual void processRexmitTimer(TcpEventCode& event) override;

    /*
     * Re-initiates pacing timer according to the pacing delay
     */
    virtual void restart_pacing_timer(int timer_type = -1);

    /*
     * Called when pacing timer expires
     */
    virtual void processPacingTimer(TcpEventCode& event, int timer_type) override;

    virtual void receivedDataAck(uint32 firstSeqAcked) override;
    virtual void rttMeasurementCompleteUsingTS(simtime_t echoedTS) override;
    virtual void receivedDuplicateAck() override;
    virtual bool sendData(bool sendCommandInvoked) override;
};

} // namespace tcp
} // namespace inet

#endif // ifndef __INET_SWIFT_H



/*
 * What should be implemented for Swift:
 * ACKs should be prioritized in switches
 * ACK Packets should piggyback the delays to the sender (This adds 4 bytes overhead to the packet headers)
 */
