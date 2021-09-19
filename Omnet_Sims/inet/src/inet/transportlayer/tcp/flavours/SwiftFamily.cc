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

#include "inet/transportlayer/tcp/Tcp.h"
#include "inet/transportlayer/tcp/flavours/SwiftFamily.h"

namespace inet {
namespace tcp {

SwiftFamilyStateVariables::SwiftFamilyStateVariables()
{
    // Initialize state variables
}

void SwiftFamilyStateVariables::setSendQueueLimit(uint32 newLimit){
    sendQueueLimit = newLimit;
}

std::string SwiftFamilyStateVariables::str() const
{
    std::stringstream out;
    out << TcpBaseAlgStateVariables::str();
    return out.str();
}

std::string SwiftFamilyStateVariables::detailedInfo() const
{
    std::stringstream out;
    out << TcpBaseAlgStateVariables::detailedInfo();
    return out.str();
}

//---

SwiftFamily::SwiftFamily() : TcpBaseAlg(),
    state((SwiftFamilyStateVariables *&)TcpAlgorithm::state)
{
}

} // namespace tcp
} // namespace inet

