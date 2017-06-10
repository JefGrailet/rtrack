/*
 * RouteRepair.cpp
 *
 *  Created on: May 10, 2017
 *      Author: jefgrailet
 *
 * Implements the class defined in RouteRepair.h (see this file to learn further about the 
 * goals of such class).
 */

#include <sstream>
using std::stringstream;
#include <iomanip>
using std::setprecision;

#include "RouteRepair.h"

RouteRepair::RouteRepair()
{
    hopBefore = InetAddress(0);
    hopAfter = InetAddress(0);
    replacement = InetAddress(0);
    online = false;
    
    nOccMissing = 0;
    nOccExisting = 0;
    
    repairedTraceExample = NULL;
    TTL = 0;
}

RouteRepair::~RouteRepair()
{
}

string RouteRepair::toString()
{
    stringstream ss;
    
    if(online)
    {
        unsigned short index = (unsigned short) TTL - 1;
        unsigned short routeSize = repairedTraceExample->getRouteSize();
        
        if(index > 0)
        {
            if(hopBefore == InetAddress(0))
                ss << "*, ";
            else
                ss << hopBefore << ", ";
        }
        ss << "*";
        if(index < routeSize - 1)
        {
            if(hopAfter == InetAddress(0))
                ss << ", *";
            else
                ss << ", " << hopAfter;
        }
        
        ss << " -> ";
        
        if(index > 0)
        {
            if(hopBefore == InetAddress(0))
                ss << "*, ";
            else
                ss << hopBefore << ", ";
        }
        ss << replacement;
        if(index < routeSize - 1)
        {
            if(hopAfter == InetAddress(0))
                ss << ", *";
            else
                ss << ", " << hopAfter;
        }
    }
    else
    {
        if(hopBefore == InetAddress(0))
        {
            if(hopAfter == InetAddress(0))
            {
                ss << "* -> " << replacement << " (single hop)";
            }
            else
            {
                ss << "*, " << hopAfter << " -> " << replacement << ", " << hopAfter;
                ss << " (beginning)";
            }
        }
        else if(hopAfter == InetAddress(0))
        {
            ss << hopBefore << ", * -> " << hopBefore << ", " << replacement << " (end)";
        }
        else
        {
            ss << hopBefore << ", *, " << hopAfter << " -> ";
            ss << hopBefore << ", " << replacement << ", " << hopAfter;
        }
    }
    
    if(!online)
    {
        double ratio = ((double) nOccExisting / ((double) nOccExisting + (double) nOccMissing)) * 100;
        ss << " (" << nOccMissing << " / " << nOccExisting << " - ";
        ss << setprecision(5) << ratio << "%)";
    }
    else
    {
        ss << " (online, " << nOccMissing << ")";
    }
    
    return ss.str();
}

bool RouteRepair::compare(RouteRepair *rr1, RouteRepair *rr2)
{
    if(rr1->hopBefore.getULongAddress() < rr2->hopBefore.getULongAddress())
        return true;
    else if(rr1->hopBefore.getULongAddress() == rr2->hopBefore.getULongAddress())
        if(rr1->hopAfter.getULongAddress() < rr2->hopAfter.getULongAddress())
            return true;
    return false;
}
