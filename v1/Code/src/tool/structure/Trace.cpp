/*
 * Trace.cpp
 *
 *  Created on: May 3, 2017
 *      Author: jefgrailet
 *
 * Implements the class defined in Trace.h (see this file to learn further about the goals of such 
 * class).
 */

#include "Trace.h"

Trace::Trace(InetAddress targetIP)
{
    this->targetIP = targetIP;
    reachable = false;
    opinionNumber = 1;
    
    routeSize = 0;
    route = NULL;
    
    processedRouteSize = 0;
    processedRoute = NULL;
}

Trace::~Trace()
{
    if(route != NULL)
        delete[] route;
    
    if(processedRoute != NULL)
        delete[] processedRoute;
}

bool Trace::hasCompleteRoute()
{
    for(unsigned short i = 0; i < routeSize; ++i)
        if(route[i].ip == InetAddress(0))
            return false;
    return true;
}

bool Trace::hasIncompleteRoute()
{
    for(unsigned short i = 0; i < routeSize; ++i)
        if(route[i].ip == InetAddress(0))
            return true;
    return false;
}

unsigned short Trace::countMissingHops()
{
    unsigned short res = 0;
    for(unsigned short i = 0; i < routeSize; ++i)
        if(route[i].ip == InetAddress(0))
            res++;
    return res;
}

bool Trace::compare(Trace *t1, Trace *t2)
{
    if(t1->getTargetIP().getULongAddress() < t2->getTargetIP().getULongAddress())
        return true;
    return false;
}

string Trace::toStringMeasured()
{
    stringstream ss;
    
    ss << "#\n";
    ss << "Target: " << targetIP;
    if(opinionNumber > 1)
        ss << " (opinion n°" << opinionNumber << ")";
    ss << "\n";
    if(!reachable)
        ss << "Unreachable\n";
    else
        ss << "TTL: " << routeSize + 1 << "\n";
    
    for(unsigned short i = 0; i < routeSize; i++)
    {
        ss << (i + 1) << " - ";
        
        unsigned short curState = route[i].state;
        if(route[i].ip != InetAddress(0))
        {
            ss << route[i].ip;
            if(curState == RouteInterface::REPAIRED_1)
                ss << " [Repaired-1]";
            else if(curState == RouteInterface::REPAIRED_2)
                ss << " [Repaired-2]";
            else if(curState == RouteInterface::LIMITED)
                ss << " [Limited]";
            else if(curState == RouteInterface::STRETCHED)
                ss << " [Stretched]";
            else if(curState == RouteInterface::CYCLE)
                ss << " [Cycle]";
        }
        else
        {
            if(curState == RouteInterface::ANONYMOUS || curState == RouteInterface::MISSING)
                ss << "Anonymous";
            else
                ss << "Skipped";
        }
        ss << "\n";
    }
    
    return ss.str();
}

string Trace::toStringPostProcessed()
{
    if(!this->isPostProcessed())
        return "";

    stringstream ss;
    
    ss << "#\n";
    ss << "Target: " << targetIP << "\n";
    
    for(unsigned short i = 0; i < processedRouteSize; i++)
    {
        ss << (i + 1) << " - ";
        
        if(processedRoute[i].ip != InetAddress(0))
            ss << processedRoute[i].ip;
        else
            ss << "Anonymous";
        ss << "\n";
    }
    
    return ss.str();
}
