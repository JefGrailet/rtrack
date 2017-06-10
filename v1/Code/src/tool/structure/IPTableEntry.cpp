/*
 * IPTableEntry.cpp
 *
 *  Created on: Sep 30, 2015
 *      Author: jefgrailet
 *
 * Implements the class defined in IPTableEntry.h (see this file to learn further about the goals 
 * of such class).
 */

#include <sstream>
using std::stringstream;
#include <iomanip>
using std::setprecision;

#include "IPTableEntry.h"

IPTableEntry::IPTableEntry(InetAddress ip) : InetAddress(ip)
{
    TTL = NO_KNOWN_TTL;
    preferredTimeout = TimeVal(DEFAULT_TIMEOUT_SECONDS, TimeVal::HALF_A_SECOND);
    
    rateLimited = false;
    
    targetForRLAnalysis = InetAddress(0);
    TTLForRLAnalysis = 0;
    
    initialTTLTimeExceeded = 0;
    initialTTLEcho = 0;
    inconsistentITTL = false;
}

IPTableEntry::~IPTableEntry()
{
}

bool IPTableEntry::hasHopCount(unsigned char hopCount)
{
    for(list<unsigned char>::iterator it = hopCounts.begin(); it != hopCounts.end(); it++)
    {
        if((*it) == hopCount)
            return true;
    }
    return false;
}

void IPTableEntry::recordHopCount(unsigned char hopCount)
{
    if(hopCount != TTL)
    {
        if(hopCount < TTL)
        {
            if(hopCounts.size() == 0)
                hopCounts.push_back(TTL);
            hopCounts.push_front(hopCount);
            TTL = hopCount;
        }
        else
        {
            if(hopCounts.size() == 0)
                hopCounts.push_back(TTL);
            hopCounts.push_back(hopCount);
        }
    }
}

void IPTableEntry::setInitialTTLTimeExceeded(unsigned char TTL)
{
    /*
     * For some reason, an IP interface probed too many times can provide a remaining TTL of 0.
     * In that case, the initial TTL for time exceeded is not modified.
     */
    
    if(TTL == 0)
        return;
    
    if(initialTTLTimeExceeded == 0)
        initialTTLTimeExceeded = TTL;
    else
        if(TTL != initialTTLTimeExceeded)
            inconsistentITTL = true;
}

bool IPTableEntry::compare(IPTableEntry *ip1, IPTableEntry *ip2)
{
    if(ip1->getULongAddress() < ip2->getULongAddress())
        return true;
    return false;
}

bool IPTableEntry::compareTTLs(unsigned char &TTL1, unsigned char &TTL2)
{
    if(TTL1 < TTL2)
        return true;
    return false;
}

string IPTableEntry::toString()
{
    stringstream ss;
    
    ss << (InetAddress) (*this) << " - " << (unsigned short) TTL << " - <";
    if(initialTTLTimeExceeded > 0 && !inconsistentITTL)
        ss << (unsigned short) initialTTLTimeExceeded;
    else
        ss << "*";
    ss << ",";
    if(initialTTLEcho > 0)
        ss << (unsigned short) initialTTLEcho;
    else
        ss << "*";
    ss << ">";
    
    if(rateLimited)
    {
        ss << " | Might be rate-limited";
        
        // Rate-limit analysis is outputted elsewhere
    }
    
    if(stretchedTTLs.size() > 0)
    {
        ss << " | Stretched [";
        
        unsigned int nTTLs = stretchedTTLs.size();
        stretchedTTLs.sort(IPTableEntry::compareTTLs);
        unsigned char prevTTL = 0;
        unsigned int countTTL = 0;
        bool guardian = true;
        for(list<unsigned char>::iterator it = stretchedTTLs.begin(); it != stretchedTTLs.end(); ++it)
        {
            unsigned char cur = (*it);
            if(cur == prevTTL)
            {
                countTTL++;
            }
            else
            {
                if(prevTTL > 0)
                {
                    double ratio = ((double) countTTL / (double) nTTLs) * 100;
                    if(guardian)
                        guardian = false;
                    else
                        ss << ", ";
                    ss << (unsigned short) prevTTL << " - " << setprecision(5) << ratio << "%";
                }
            
                prevTTL = cur;
                countTTL = 1;
            }
        }
        
        // Last one
        double ratio = ((double) countTTL / (double) nTTLs) * 100;
        if(guardian)
            guardian = false;
        else
            ss << ", ";
        ss << (unsigned short) prevTTL << " - " << setprecision(5) << ratio << "%";
        
        ss << "]";
    }
    
    if(inCyclesTTLs.size() > 0)
    {
        ss << " | Cycling [";
        
        unsigned int nTTLs = inCyclesTTLs.size();
        inCyclesTTLs.sort(IPTableEntry::compareTTLs);
        unsigned char prevTTL = 0;
        unsigned int countTTL = 0;
        bool guardian = true;
        for(list<unsigned char>::iterator it = inCyclesTTLs.begin(); it != inCyclesTTLs.end(); ++it)
        {
            unsigned char cur = (*it);
            if(cur == prevTTL)
            {
                countTTL++;
            }
            else
            {
                if(prevTTL > 0)
                {
                    double ratio = ((double) countTTL / (double) nTTLs) * 100;
                    if(guardian)
                        guardian = false;
                    else
                        ss << ", ";
                    ss << (unsigned short) prevTTL << " - " << setprecision(5) << ratio << "%";
                }
            
                prevTTL = cur;
                countTTL = 1;
            }
        }
        
        // Last one
        double ratio = ((double) countTTL / (double) nTTLs) * 100;
        if(guardian)
            guardian = false;
        else
            ss << ", ";
        ss << (unsigned short) prevTTL << " - " << setprecision(5) << ratio << "%";
        
        ss << "]";
    }
    
    ss << "\n";
    
    return ss.str();
}

string IPTableEntry::toStringFingerprint()
{
    stringstream ss;
    
    ss << (InetAddress) (*this) << " - <";
    if(initialTTLTimeExceeded > 0 && !inconsistentITTL)
        ss << (unsigned short) initialTTLTimeExceeded;
    else
        ss << "*";
    ss << ",";
    if(initialTTLEcho > 0)
        ss << (unsigned short) initialTTLEcho;
    else
        ss << "*";
    ss << ">";
    
    ss << "\n";
    
    return ss.str();
}
