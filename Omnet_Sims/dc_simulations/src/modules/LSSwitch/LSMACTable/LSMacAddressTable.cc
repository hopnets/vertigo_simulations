// Copyright (C) 2013 OpenSim Ltd.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
//

#include <map>

#include "inet/common/ModuleAccess.h"
#include "inet/common/StringFormat.h"
#include "./LSMacAddressTable.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/networklayer/contract/IInterfaceTable.h"

using namespace inet;

#define MAX_LINE    1000000

Define_Module(LSMacAddressTable);

std::ostream& operator<<(std::ostream& os, const LSMacAddressTable::AddressEntry& entry)
{
    for (std::list<simtime_t>::const_iterator it=entry.insertionTimeList.begin(); it != entry.insertionTimeList.end(); ++it){
        std::list<int>::const_iterator it2=entry.interfaceList.begin();
        os << "{VID=" << entry.vid << ", interfaceList=" << *it2 << ", insertionTimeList=" << *it << "}";
        it2++;
    }
    return os;
}

LSMacAddressTable::LSMacAddressTable()
{
}

void LSMacAddressTable::initialize(int stage)
{
    OperationalBase::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        agingTime = par("agingTime");
        lastPurge = SIMTIME_ZERO;
        ifTable = getModuleFromPar<IInterfaceTable>(par("interfaceTableModule"), this);
    }
}

/**
 * Function reads from a file stream pointed to by 'fp' and stores characters
 * until the '\n' or EOF character is found, the resultant string is returned.
 * Note that neither '\n' nor EOF character is stored to the resultant string,
 * also note that if on a line containing useful data that EOF occurs, then
 * that line will not be read in, hence must terminate file with unused line.
 */
static char *fgetline(FILE *fp)
{
    // alloc buffer and read a line
    char *line = new char[MAX_LINE];
    if (fgets(line, MAX_LINE, fp) == nullptr) {
        delete[] line;
        return nullptr;
    }

    // chop CR/LF
    line[MAX_LINE - 1] = '\0';
    int len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
        line[--len] = '\0';

    return line;
}

void LSMacAddressTable::handleMessage(cMessage *)
{
    throw cRuntimeError("This module doesn't process messages");
}

void LSMacAddressTable::handleMessageWhenUp(cMessage *)
{
    throw cRuntimeError("This module doesn't process messages");
}

void LSMacAddressTable::refreshDisplay() const
{
    updateDisplayString();
}

void LSMacAddressTable::updateDisplayString() const
{
    auto text = StringFormat::formatString(par("displayStringTextFormat"), [&] (char directive) {
        static std::string result;
        switch (directive) {
        case 'a':
            result = addressTable ? std::to_string(addressTable->size()) : "0";
            break;
        case 'v':
            result = std::to_string(vlanAddressTable.size());
            break;
        default:
            throw cRuntimeError("Unknown directive: %c", directive);
        }
        return result.c_str();
    });
    getDisplayString().setTagArg("t", 0, text);
}

/*
 * getTableForVid
 * Returns a MAC Address Table for a specified VLAN ID
 * or nullptr pointer if it is not found
 */

LSMacAddressTable::AddressTable *LSMacAddressTable::getTableForVid(unsigned int vid)
{
    if (vid == 0)
        return addressTable;

    auto iter = vlanAddressTable.find(vid);
    if (iter != vlanAddressTable.end())
        return iter->second;
    return nullptr;
}

std::list<int> LSMacAddressTable::getInterfaceIdForAddress(const MacAddress& address, unsigned int vid)
{
    Enter_Method("LSMacAddressTable::getPortForAddress()");

    AddressTable *table = getTableForVid(vid);
    // VLAN ID vid does not exist
    std::list<int> interfaces;
    if (table == nullptr)
        return interfaces;

    auto iter = table->find(address);

    if (iter == table->end()) {
        // not found
        return interfaces;
    }

    for (std::list<simtime_t>::iterator it=iter->second.insertionTimeList.begin(); it != iter->second.insertionTimeList.end();){
        std::list<int>::iterator it2=iter->second.interfaceList.begin();
        if (*it + agingTime <= simTime()) {
            // don't use (and throw out) aged entries
            EV << "Ignoring and deleting aged entry: " << iter->first << " --> interfaceId " << *it2 << "\n";
            //                table->erase(iter);
//            iter->second.interfaceList.remove(*it2);
//            iter->second.insertionTimeList.remove(*it);
            //return iter->second.interfaceList;
            it = iter->second.insertionTimeList.erase(it);
            it2 = iter->second.interfaceList.erase(it2);
        }
        else {
            it2++;
            it++;
        }

    }

    return iter->second.interfaceList;
}

/*
 * get the list of simTimes related to a spesific mac address
 */
std::list<simtime_t> LSMacAddressTable::getInsertionTimeForAddress(const MacAddress& address, unsigned int vid)
{
    Enter_Method("LSMacAddressTable::getInsertionTimeForAddress()");

    AddressTable *table = getTableForVid(vid);
    // VLAN ID vid does not exist
    std::list<simtime_t> insertionTime;
    if (table == nullptr)
        return insertionTime;

    auto iter = table->find(address);

    if (iter == table->end()) {
        // not found
        return insertionTime;
    }
    for (std::list<simtime_t>::iterator it=iter->second.insertionTimeList.begin(); it != iter->second.insertionTimeList.end(); ++it){
        std::list<int>::iterator it2=iter->second.interfaceList.begin();
        if (*it + agingTime <= simTime()) {
            // don't use (and throw out) aged entries
            EV << "Ignoring and deleting aged entry: " << iter->first << " --> interfaceId " << *it2 << "\n";
            //                table->erase(iter);
            iter->second.interfaceList.remove(*it2);
            iter->second.insertionTimeList.remove(*it);
            //return insertionTime;
        }
        it2++;
    }

    return iter->second.insertionTimeList;
}

/*
 * Prints verbose information
 */

void LSMacAddressTable::printState()
{
    EV << endl << "MAC Address Table" << endl;
    EV << "VLAN ID    MAC    IfId    Inserted" << endl;
    for (auto & elem : vlanAddressTable) {
        AddressTable *table = elem.second;
        for (auto & table_j : *table){
            std::list<simtime_t>::iterator it2=table_j.second.insertionTimeList.begin();
            for (std::list<int>::iterator it=table_j.second.interfaceList.begin(); it != table_j.second.interfaceList.end(); ++it){
                EV << table_j.second.vid << "   " << table_j.first << "   " << *it << "   " << *it2 <<  endl;
                it2++;
            }

        }
        //            EV << table_j.second.vid << "   " << table_j.first << "   " << table_j.second.interfaceId << "   " << table_j.second.insertionTime << endl;
    }
}

/*
 * Register a new MAC address at addressTable.
 * True if refreshed. False if it is new.
 */

bool LSMacAddressTable::updateTableWithAddress(int interfaceId, const MacAddress& address, unsigned int vid)
{
    Enter_Method("LSMacAddressTable::updateTableWithAddress()");

    EV << "SEPEHR: updateTableWithAddress called for address: " << address << endl;
    if (address.isMulticast())      // broadcast or multicast
        return false;

    AddressTable::iterator iter;
    AddressTable *table = getTableForVid(vid);

    if (table == nullptr) {
        // MAC Address Table does not exist for VLAN ID vid, so we create it
        table = new AddressTable();

        // set 'the addressTable' to VLAN ID 0
        if (vid == 0)
            addressTable = table;

        vlanAddressTable[vid] = table;
        iter = table->end();
    }
    else
        iter = table->find(address);

    if (iter == table->end()) {
        removeAgedEntriesIfNeeded();


        // Add entry to table
        EV << "Adding entry to Address Table: " << address << " --> interfaceId " << interfaceId << "\n";
        std::list<int> interfaceList;
        std::list<simtime_t> insertionTime;
        interfaceList.push_back(interfaceId);
        insertionTime.push_back(simTime());
        (*table)[address] = AddressEntry(vid, interfaceList, insertionTime);
        return false;
    }
    else {
        // Update existing entry

        EV << "Updating entry in Address Table: " << address << " --> interfaceId " << interfaceId << "\n";
        bool interfaceExist = false;
        AddressEntry& entry = iter->second;

        for (std::list<int>::iterator it=entry.interfaceList.begin(); it != entry.interfaceList.end(); ++it){
            EV << "SOUGOL: InterfaceList element: "<< *it << endl;
            for (std::list<simtime_t>::iterator it2=entry.insertionTimeList.begin(); it2 != entry.insertionTimeList.end(); ++it2){
                EV << "SOUGOL: InsertionTimeList element: "<< *it2 << endl;
            }
            std::list<simtime_t>::iterator it2=entry.insertionTimeList.begin();
            if(*it == interfaceId) {
                EV << "SOUGOL: Updating the in case where the interface id is in the MAC Table(just updating the insertion time)" << endl;
                *it2 = simTime();
                interfaceExist = true;
                this->printState();
                break;
            }
            it2++;
        }
        if (!interfaceExist) {
            EV << "SOUGOL: Updating the in case where the interface id is not in the MAC Table(Adding one other entry)" << endl;
            entry.insertionTimeList.push_back(simTime());
            entry.interfaceList.push_back(interfaceId);
            this->printState();
        }
    }
    return true;
}

/*
 * Clears interfaceId MAC cache.
 */

void LSMacAddressTable::flush(int interfaceId)
{
    Enter_Method("LSMacAddressTable::flush():  Clearing interfaceId %d cache", interfaceId);
    for (auto & elem : vlanAddressTable) {
        AddressTable *table = elem.second;
        for (auto j = table->begin(); j != table->end(); ) {
            auto cur = j++;
            for (std::list<int>::iterator it=cur->second.interfaceList.begin(); it != cur->second.interfaceList.end(); ++it){
                if (*it == interfaceId){
                    cur->second.interfaceList.remove(interfaceId);
                }
                table->erase(cur);
            }
            //            if (cur->second.interfaceId == interfaceId)
            //                table->erase(cur);
        }
    }
}



void LSMacAddressTable::copyTable(int interfaceIdA, int interfaceIdB)
{
    for (auto & elem : vlanAddressTable) {
        AddressTable *table = elem.second;
        for (auto & table_j : *table){
            for (std::list<int>::iterator it=table_j.second.interfaceList.begin(); it != table_j.second.interfaceList.end(); ++it){
                if (*it == interfaceIdA){
                    table_j.second.interfaceList.remove(*it);
                    //MY understanding is that it should also update the time corresponded to the interfaceport
                    //                    table_j.second.insertionTimeList
                    table_j.second.interfaceList.push_back(interfaceIdB);
                }
            }

        }
        //            if (table_j.second.interfaceId == interfaceIdA)
        //                table_j.second.interfaceId = interfaceIdB;

    }
}

void LSMacAddressTable::removeAgedEntriesFromVlan(unsigned int vid)
{
    AddressTable *table = getTableForVid(vid);

    if (table == nullptr)
        return;
    // TODO: this part could be factored out
    for (auto iter = table->begin(); iter != table->end(); ) {
        auto cur = iter++;    // iter will get invalidated after erase()
        AddressEntry& entry = cur->second;
        std::list<simtime_t>::iterator it2=entry.insertionTimeList.begin();
        for (std::list<int>::iterator it=entry.interfaceList.begin(); it != entry.interfaceList.end(); ){
            if(*it2 + agingTime <= simTime()){
                EV << "Removing aged entry from Address Table: "
                        << cur->first << " --> interfaceId " << *it << "\n";
                it = entry.interfaceList.erase(it);
                it2 = entry.insertionTimeList.erase(it2);

            }
            else {
                it++;
                it2++;
            }
        }
        //        if (entry.insertionTime + agingTime <= simTime()) {
        //            EV << "Removing aged entry from Address Table: "
        //                    << cur->first << " --> interfaceId " << cur->second.interfaceId << "\n";
        //            table->erase(cur);
    }
}


void LSMacAddressTable::removeAgedEntriesFromAllVlans()
{
    for (auto & elem : vlanAddressTable) {
        AddressTable *table = elem.second;
        // TODO: this part could be factored out

        for (auto j = table->begin(); j != table->end(); ) {
            auto cur = j++;    // iter will get invalidated after erase()
            AddressEntry& entry = cur->second;
            std::list<simtime_t>::iterator it2=entry.insertionTimeList.begin();
            for (std::list<int>::iterator it=entry.interfaceList.begin(); it != entry.interfaceList.end(); ){
                printState();
                if(*it2 + agingTime <= simTime()){
                    EV << "Removing aged entry from Address Table: "
                            << cur->first << " --> interfaceId " << *it << "\n";
                    it = entry.interfaceList.erase(it);
                    it2 = entry.insertionTimeList.erase(it2);

                }
                else {
                    it++;
                    it2++;
                }
            }
        }
    }
}

void LSMacAddressTable::removeAgedEntriesIfNeeded()
{
    simtime_t now = simTime();

    if (now >= lastPurge + 1)
        removeAgedEntriesFromAllVlans();

    lastPurge = simTime();
}
//TODO: should be changed!!!! you should update the list, not just add!!
void LSMacAddressTable::readAddressTable(const char *fileName)
{
    FILE *fp = fopen(fileName, "r");
    if (fp == nullptr)
        throw cRuntimeError("cannot open address table file `%s'", fileName);

    // parse address table file:
    char *line;
    for (int lineno = 0; (line = fgetline(fp)) != nullptr; delete [] line) {
        lineno++;

        // lines beginning with '#' are treated as comments
        if (line[0] == '#')
            continue;

        // scan in VLAN ID
        char *vlanIdStr = strtok(line, " \t");
        // scan in MAC address
        char *macAddressStr = strtok(nullptr, " \t");
        // scan in interface name
        char *interfaceName = strtok(nullptr, " \t");

        char *endptr = nullptr;

        // empty line or comment?
        if (!vlanIdStr || *vlanIdStr == '#')
            continue;

        // broken line?
        if (!vlanIdStr || !macAddressStr || !interfaceName)
            throw cRuntimeError("line %d invalid in address table file `%s'", lineno, fileName);

        // parse columns:

        //   parse VLAN ID:
        unsigned int vlanId = strtol(vlanIdStr, &endptr, 10);
        if (!endptr || *endptr)
            throw cRuntimeError("error in line %d in address table file `%s': VLAN ID '%s' unresolved", lineno, fileName, vlanIdStr);

        //   parse MAC address:
        L3Address addr;
        if (! L3AddressResolver().tryResolve(macAddressStr, addr, L3AddressResolver::ADDR_MAC))
            throw cRuntimeError("error in line %d in address table file `%s': MAC address '%s' unresolved", lineno, fileName, macAddressStr);
        MacAddress macAddress = addr.toMac();

        //   parse interface:
        int interfaceId = -1;
        auto ie = ifTable->findInterfaceByName(interfaceName);
        if (ie == nullptr) {
            long int num = strtol(interfaceName, &endptr, 10);
            if (endptr && *endptr == '\0') {
                ie = ifTable->findInterfaceById(num);
            }
        }
        if (ie == nullptr)
            throw cRuntimeError("error in line %d in address table file `%s': interface '%s' not found", lineno, fileName, interfaceName);
        interfaceId = ie->getInterfaceId();

        // Create an entry with address and interfaceId and insert into table
        // FIRST CHECK IF THE MAC ADDRESS ALREADY HAS AN ENTRY
        std::list<int> interfaceList;
        std::list<simtime_t> insertionTime;
        interfaceList.push_back(interfaceId);
        insertionTime.push_back(0);
        AddressEntry entry(vlanId, interfaceList, insertionTime);
        AddressTable *table = getTableForVid(entry.vid);

        if (table == nullptr) {
            // MAC Address Table does not exist for VLAN ID vid, so we create it
            table = new AddressTable();

            // set 'the addressTable' to VLAN ID 0
            if (entry.vid == 0)
                addressTable = table;

            vlanAddressTable[entry.vid] = table;
        }
        if ((*table)[macAddress].insertionTimeList.size() == 0){
            (*table)[macAddress] = entry;
        }
        else {
            AddressEntry& entry = (*table)[macAddress];
            entry.insertionTimeList.push_back(0);
            entry.interfaceList.push_back(interfaceId);
//            std::list<int> interfaceL = getInterfaceIdForAddress(macAddress, vlanId);
//            std::list<simtime_t> insertionT = getInsertionTimeForAddress(macAddress, vlanId);
//            interfaceL.push_back(interfaceId);
//            insertionT.push_back(0);
        }
    }
    fclose(fp);
}

void LSMacAddressTable::initializeTable()
{
    clearTable();
    // Option to pre-read in Address Table. To turn it off, set addressTableFile to empty string
    const char *addressTableFile = par("addressTableFile");

    if (addressTableFile && *addressTableFile)
        readAddressTable(addressTableFile);

    if (this->addressTable != nullptr) {  // setup a WATCH on VLANID 0 if present
        AddressTable& addressTable = *this->addressTable;    // magic to hide the '*' from the name of the watch below
        WATCH_MAP(addressTable);
    }
}

void LSMacAddressTable::clearTable()
{
    for (auto & elem : vlanAddressTable)
        delete elem.second;

    vlanAddressTable.clear();
    addressTable = nullptr;
}

LSMacAddressTable::~LSMacAddressTable()
{
    for (auto & elem : vlanAddressTable)
        delete elem.second;
}

void LSMacAddressTable::setAgingTime(simtime_t agingTime)
{
    this->agingTime = agingTime;
}

void LSMacAddressTable::resetDefaultAging()
{
    agingTime = par("agingTime");
}

// namespace inet

