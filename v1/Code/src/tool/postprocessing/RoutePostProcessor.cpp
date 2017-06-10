/*
 * RoutePostProcessor.cpp
 *
 *  Created on: May 4, 2017
 *      Author: jefgrailet
 *
 * Implements the class defined in RoutePostProcessor.h (see this class for more details).
 */

#include <list>
using std::list;

#include <map>
using std::map;
using std::pair;

#include "RoutePostProcessor.h"

RoutePostProcessor::RoutePostProcessor(ToolEnvironment *env)
{
    this->env = env;
    
    printSteps = false;
    if(env->getDisplayMode() >= ToolEnvironment::DISPLAY_MODE_SLIGHTLY_VERBOSE)
        printSteps = true;
}

RoutePostProcessor::~RoutePostProcessor()
{
}

void RoutePostProcessor::process()
{
    this->detect();
    this->mitigate();
}

void RoutePostProcessor::detect()
{
    ostream *out = env->getOutputStream();
    list<Trace*> *traces = env->getTraces();
    IPLookUpTable *dict = env->getIPTable();
    
    // Evaluates route cycling
    unsigned short totalAffectedTraces = 0;
    (*out) << "Evaluating route cycling..." << endl;
    for(list<Trace*>::iterator it = traces->begin(); it != traces->end(); ++it)
    {
        Trace *curTrace = (*it);
        if(curTrace->hasValidRoute())
        {
            this->checkForCycles(curTrace);
            unsigned short longestCycle = 0;
            unsigned short nbCycles = this->countCycles(curTrace, &longestCycle);
            if(nbCycles > 0)
            {
                totalAffectedTraces++;
                if(nbCycles > 1)
                    (*out) << "Found " << nbCycles << " cycles";
                else
                    (*out) << "Found one cycle";
                (*out) << " in route to " << curTrace->getTargetIP() << " (";
                if(nbCycles > 1)
                    (*out) << "maximum ";
                (*out) << "cycle length: " << longestCycle << ")." << endl;
            }
        }
    }
    if(totalAffectedTraces > 0)
        (*out) << "Done.\n" << endl;
    else
        (*out) << "No router suffers from route cycling.\n" << endl;
    
    // Evaluates route stretching
    totalAffectedTraces = 0;
    (*out) << "Evaluating route stretching..." << endl;
    for(list<Trace*>::iterator it = traces->begin(); it != traces->end(); ++it)
    {
        Trace *curTrace = (*it);
        unsigned short nbStretches = 0;
        unsigned short maxStretch = 0;
        if(curTrace->hasValidRoute())
        {
            unsigned short routeSize = curTrace->getRouteSize();
            RouteInterface *route = curTrace->getRoute();
            for(unsigned short i = 0; i < routeSize; i++)
            {
                InetAddress hop = route[i].ip;
                if(hop == InetAddress(0) || route[i].state == RouteInterface::CYCLE)
                    continue;
                
                IPTableEntry *IPEntry = dict->lookUp(hop);
                if(IPEntry == NULL) // Should not occur, but just in case, if it does, we skip
                    continue;
                
                unsigned short shortestTTL = (unsigned short) IPEntry->getTTL();
                if((i + 1) > shortestTTL)
                {
                    unsigned short diff = (i + 1) - shortestTTL;
                    route[i].state = RouteInterface::STRETCHED;
                    
                    IPEntry->addStretchedTTL((unsigned char) (i + 1));
                    
                    nbStretches++;
                    if(diff > maxStretch)
                        maxStretch = diff;
                }
            }
            
            if(nbStretches > 0)
            {
                totalAffectedTraces++;
                if(nbStretches > 1)
                    (*out) << "Found " << nbStretches << " stretches";
                else
                    (*out) << "Found one stretch";
                (*out) << " in route to " << curTrace->getTargetIP() << " (";
                if(nbStretches > 1)
                    (*out) << "longest ";
                if(maxStretch > 1)
                    (*out) << "stretch: " << maxStretch << " hops)." << endl;
                else
                    (*out) << "stretch: " << maxStretch << " hop)." << endl;
            }
        }
    }
    if(totalAffectedTraces > 0)
        (*out) << "Done.\n" << endl;
    else
        (*out) << "No router suffers from route stretching.\n" << endl;
}

void RoutePostProcessor::mitigate()
{
    ostream *out = env->getOutputStream();
    list<Trace*> *tList = env->getTraces();

    /*
     * Step 1: preparation
     * -------------------
     *
     * In order to avoid useless processing in subsequent steps, the method first lists the 
     * traces which need post-processing.
     */
    
    list<Trace*> traces;
    map<InetAddress, Trace*> mapTraces;
    for(list<Trace*>::iterator it = tList->begin(); it != tList->end(); ++it)
    {
        Trace *curTrace = (*it);
        if(curTrace->hasValidRoute())
            if(this->needsPostProcessing(curTrace))
                traces.push_back(curTrace);
    }
    
    // Checks if there are routes to post-process at all.
    size_t nbRoutesToFix = traces.size();
    if(nbRoutesToFix > 0)
    {
        if(nbRoutesToFix > 1)
            (*out) << "There are " << nbRoutesToFix << " routes to post-process." << endl;
        else
            (*out) << "There is one route to post-process." << endl;
    }
    else
    {
        return;
    }
    
    /*
     * Step 2: route cycling mitigation
     * --------------------------------
     */
    
    unsigned short cycleFixed = 0;
    for(list<Trace*>::iterator it = traces.begin(); it != traces.end(); ++it)
    {
        Trace *trace = (*it);
        if(this->needsCyclingMitigation(trace))
        {
            unsigned short prevRouteSize = trace->getRouteSize(), newRouteSize = 0;
            RouteInterface *prevRoute = trace->getRoute(), *newRoute = NULL;

            if(printSteps)
            {
                (*out) << "Mitigating cycle(s) in route to " << trace->getTargetIP();
                (*out) << " (" << prevRouteSize << " hops)..." << endl;
            }
            
            // As long as there remains cycle(s) in the route...
            while(this->hasCycle(prevRoute, prevRouteSize))
            {
                // Starts from the end to find a cycle
                unsigned short cycleStart = 0, cycleEnd = 0;
                for(short int i = prevRouteSize - 1; i >= 0; i--)
                {
                    if(prevRoute[i].state == RouteInterface::CYCLE)
                    {
                        cycleEnd = i;
                        break;
                    }
                }
                InetAddress cycledIP = prevRoute[cycleEnd].ip;
                
                if(cycleEnd == 0) // Just in case
                    break;
                
                if(printSteps)
                {
                    (*out) << "Found a cycled IP (" << cycledIP << ") at TTL = ";
                    (*out) << (cycleEnd + 1) << "." << endl;
                }
                
                // Gets start of the cycle
                for(short int i = cycleEnd - 1; i >= 0; i--)
                    if(prevRoute[i].ip == prevRoute[cycleEnd].ip)
                        cycleStart = i;
                
                if(printSteps)
                {
                    (*out) << "Found start of the cycle at TTL = ";
                    (*out) << (cycleEnd + 1) << "." << endl;
                }
                
                // Lists hops before and after the cycle
                list<RouteInterface> newHops;
                for(unsigned short i = 0; i < cycleStart; i++)
                    newHops.push_back(prevRoute[i]);
                for(unsigned short i = cycleEnd; i < prevRouteSize; i++)
                    newHops.push_back(prevRoute[i]);
                
                // Creates the new route
                unsigned short index = 0;
                newRouteSize = (unsigned short) newHops.size();
                newRoute = new RouteInterface[newRouteSize];
                
                if(printSteps)
                    (*out) << "New route size is " << newRouteSize << " hops." << endl;
                
                while(newHops.size() > 0)
                {
                    newRoute[index] = newHops.front();
                    newHops.pop_front();
                    if(newRoute[index].ip == cycledIP)
                        newRoute[index].state = RouteInterface::VIA_TRACEROUTE;
                    index++;
                }
                
                prevRouteSize = newRouteSize;
                prevRoute = newRoute;
            }
            
            if(newRoute != NULL)
            {
                cycleFixed++;
                trace->setProcessedRouteSize(newRouteSize);
                trace->setProcessedRoute(newRoute);
            }
            
            if(printSteps)
                (*out) << "Done with route to " << trace->getTargetIP() << "." << endl;
            
            // If no other needs, we remove this trace from the list for the last step
            if(!this->needsStretchingMitigation(trace))
            {
                traces.erase(it--);
            }
        }
    }
    if(cycleFixed > 0)
    {
        (*out) << "Mitigated route cycling on ";
        if(cycleFixed > 1)
            (*out) << cycleFixed << " routes.";
        else
            (*out) << "one route.";
        (*out) << endl;
    }
    
    /*
     * Step 3: route stretching mitigation
     * -----------------------------------
     */
    
    unsigned short stretchFixed = 0;
    for(list<Trace*>::iterator it = traces.begin(); it != traces.end(); ++it)
    {
        Trace *trace = (*it);
        
        // There should be no need to check that the route needs mitigation.
        
        bool firstRouteMeasured = true;
        if(trace->getProcessedRouteSize() > 0 && trace->getProcessedRoute() != NULL)
            firstRouteMeasured = false;
        
        unsigned short prevRouteSize = 0, newRouteSize = 0;
        RouteInterface *prevRoute = NULL, *newRoute = NULL;
        if(firstRouteMeasured)
        {
            prevRouteSize = trace->getRouteSize();
            prevRoute = trace->getRoute();
        }
        else
        {
            prevRouteSize = trace->getProcessedRouteSize();
            prevRoute = trace->getProcessedRoute();
        }
        
        if(printSteps)
        {
            (*out) << "Mitigating stretch(es) in route to " << trace->getTargetIP();
            (*out) << " (" << prevRouteSize << " hops)..." << endl;
        }
        
        // As long as there remains stretch(es) in the route...
        while(this->hasStretch(prevRoute, prevRouteSize))
        {
            // Starts from the end to find a stretched IP
            unsigned short stretchOffset = 0;
            for(short int i = prevRouteSize - 1; i >= 0; i--)
            {
                if(prevRoute[i].state == RouteInterface::STRETCHED)
                {
                    stretchOffset = i;
                    break;
                }
            }
            InetAddress IPToFix = prevRoute[stretchOffset].ip;
            
            if(stretchOffset == 0) // Just in case
                continue;
            
            if(printSteps)
            {
                (*out) << "Found a stretched IP (" << IPToFix << ") at TTL = ";
                (*out) << (stretchOffset + 1) << "." << endl;
            }
            
            // Now looks for the route prefix of the earliest occurrence of that IP
            unsigned short prefixSize = 0;
            RouteInterface *prefix = this->findPrefix(IPToFix, &prefixSize);
            if(prefix != NULL)
            {
                if(printSteps)
                {
                    (*out) << "Found new route prefix (length = " << prefixSize;
                    (*out) << " hops)." << endl;
                }
            }
            
            // Lists hops before and after the stretch
            list<RouteInterface> newHops;
            for(unsigned short i = 0; i < prefixSize; i++)
                newHops.push_back(prefix[i]);
            for(unsigned short i = stretchOffset; i < prevRouteSize; i++)
                newHops.push_back(prevRoute[i]);
            
            // Creates the new route
            unsigned short index = 0;
            newRouteSize = (unsigned short) newHops.size();
            newRoute = new RouteInterface[newRouteSize];
            
            if(printSteps)
                (*out) << "New route length is " << newRouteSize << " hops." << endl;
            
            while(newHops.size() > 0)
            {
                newRoute[index] = newHops.front();
                newHops.pop_front();
                if(newRoute[index].ip == IPToFix)
                    newRoute[index].state = RouteInterface::VIA_TRACEROUTE;
                index++;
            }
            
            // If the "prevRoute" is initially the measured route, we should NOT delete it
            if(firstRouteMeasured)
                firstRouteMeasured = false;
            else
                delete[] prevRoute;
            
            prevRouteSize = newRouteSize;
            prevRoute = newRoute;
        }
        
        if(newRoute != NULL)
        {
            stretchFixed++;
            trace->setProcessedRouteSize(newRouteSize);
            trace->setProcessedRoute(newRoute);
        }
        
        if(printSteps)
            (*out) << "Done with route to " << trace->getTargetIP() << "." << endl;
    }
    if(stretchFixed > 0)
    {
        (*out) << "Mitigated route stretching on ";
        if(stretchFixed > 1)
            (*out) << stretchFixed << " routes.";
        else
            (*out) << "one route.";
        (*out) << endl;
    }
    
    (*out) << endl;
}

void RoutePostProcessor::checkForCycles(Trace *t)
{
    IPLookUpTable *IPDict = env->getIPTable();

    unsigned short routeSize = t->getRouteSize();
    RouteInterface *route = t->getRoute();
    for(unsigned short i = 0; i < routeSize; ++i)
    {
        if(route[i].state == RouteInterface::CYCLE || route[i].ip == InetAddress(0))
            continue;
    
        InetAddress curStep = route[i].ip;
        for(unsigned short j = i + 1; j < routeSize; ++j)
        {
            InetAddress nextStep = route[j].ip;
            if(curStep == nextStep)
            {
                route[j].state = RouteInterface::CYCLE;
                
                IPTableEntry *IPEntry = IPDict->lookUp(curStep);
                if(IPEntry != NULL)
                    IPEntry->addInCycleTTL((unsigned char) (j + 1));
            }
        }
    }
}

unsigned short RoutePostProcessor::countCycles(Trace *t, unsigned short *longest)
{
    unsigned short routeSize = t->getRouteSize();
    RouteInterface *route = t->getRoute();
    
    unsigned short nbCycles = 0, longestCycle = 0;
    bool toIgnore[routeSize];
    for(unsigned short i = 0; i < routeSize; i++)
        toIgnore[i] = false;
    
    for(short int i = routeSize - 1; i >= 0; --i)
    {
        if(toIgnore[i])
            continue;
    
        if(route[i].state == RouteInterface::CYCLE)
        {
            nbCycles++;
            InetAddress curIP = route[i].ip;
            unsigned short cycleLength = 0;
            for(short int j = i - 1; j >= 0; --j)
            {
                if(route[j].ip == curIP)
                {
                    cycleLength = i - j;
                    toIgnore[j] = true;
                }
            }
            
            if(cycleLength > longestCycle)
                longestCycle = cycleLength;
        }
    }
    (*longest) = longestCycle;
    return nbCycles;
}

bool RoutePostProcessor::needsPostProcessing(Trace *t)
{
    unsigned short routeSize = t->getRouteSize();
    RouteInterface *route = t->getRoute();

    for(unsigned short i = 0; i < routeSize; ++i)
        if(route[i].state == RouteInterface::CYCLE || route[i].state == RouteInterface::STRETCHED)
            return true;
    
    return false;
}

bool RoutePostProcessor::needsCyclingMitigation(Trace *t)
{
    unsigned short routeSize = t->getRouteSize();
    RouteInterface *route = t->getRoute();

    for(unsigned short i = 0; i < routeSize; ++i)
        if(route[i].state == RouteInterface::CYCLE)
            return true;
    
    return false;
}

bool RoutePostProcessor::needsStretchingMitigation(Trace *t)
{
    unsigned short routeSize = t->getRouteSize();
    RouteInterface *route = t->getRoute();

    for(unsigned short i = 0; i < routeSize; ++i)
        if(route[i].state == RouteInterface::STRETCHED)
            return true;
    
    return false;
}

bool RoutePostProcessor::hasCycle(RouteInterface *route, unsigned short size)
{
    for(unsigned short i = 0; i < size; ++i)
        if(route[i].state == RouteInterface::CYCLE)
            return true;
    
    return false;
}

bool RoutePostProcessor::hasStretch(RouteInterface *route, unsigned short size)
{
    for(unsigned short i = 0; i < size; ++i)
        if(route[i].state == RouteInterface::STRETCHED)
            return true;
    
    return false;
}

RouteInterface* RoutePostProcessor::findPrefix(InetAddress stretched, unsigned short *size)
{
    IPLookUpTable *dict = env->getIPTable();
    list<Trace*> *traces = env->getTraces();
    
    // 1) Finds shortest TTL seen for this hop
    IPTableEntry *hop = dict->lookUp(stretched);
    if(hop == NULL)
        return NULL;
    
    unsigned char TTL = hop->getTTL();
    
    // 2) Inspects the routes of all traces at that given hop
    for(list<Trace*>::iterator it = traces->begin(); it != traces->end(); ++it)
    {
        Trace *curTrace = (*it);
        if(curTrace->hasValidRoute())
        {
            // 2.1) The stretched IP appears "in the middle" of the route
            if(curTrace->getRouteSize() >= (unsigned short) TTL)
            {
                RouteInterface *route = curTrace->getRoute();
                if(route[(unsigned short) TTL - 1].ip == stretched)
                {
                    (*size) = (unsigned short) TTL - 1;
                    return route;
                }
            }
            // 2.2) The stretched IP is the target of the route; whole route is given
            else if(curTrace->getRouteSize() == (unsigned short) (TTL - 1))
            {
                if(curTrace->getTargetIP() == stretched)
                {
                    (*size) = (unsigned short) TTL - 1;
                    return curTrace->getRoute();
                }
            }
                        
            // 2.2) is analoguous to looking for a stretched IP among subnets in TreeNET.
        }
    }
    
    return NULL;
}
