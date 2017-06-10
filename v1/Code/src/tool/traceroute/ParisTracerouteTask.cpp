/*
 * ParisTracerouteTask.cpp
 *
 *  Created on: Mar 16, 2015
 *      Author: jefgrailet
 *
 * Implements the class defined in ParisTracerouteTask.h (see this file to learn further about the 
 * goals of such class).
 */

#include "ParisTracerouteTask.h"
#include "../structure/RouteInterface.h"

ParisTracerouteTask::ParisTracerouteTask(ToolEnvironment *e, 
                                         InetAddress t, 
                                         unsigned short lbii, 
                                         unsigned short ubii, 
                                         unsigned short lbis, 
                                         unsigned short ubis) throw (SocketException):
env(e)
{
    try
    {
        unsigned short protocol = env->getProbingProtocol();
    
        if(protocol == ToolEnvironment::PROBING_PROTOCOL_UDP)
        {
            int roundRobinSocketCount = 1;
            
            prober = new DirectUDPWrappedICMPProber(env->getAttentionMessage(), 
                                                    roundRobinSocketCount, 
                                                    env->getTimeoutPeriod(), 
                                                    env->getProbeRegulatingPeriod(), 
                                                    lbii, 
                                                    ubii, 
                                                    lbis, 
                                                    ubis, 
                                                    env->debugMode());
        }
        else if(protocol == ToolEnvironment::PROBING_PROTOCOL_TCP)
        {
            int roundRobinSocketCount = 1;
            
            prober = new DirectTCPWrappedICMPProber(env->getAttentionMessage(), 
                                                    roundRobinSocketCount, 
                                                    env->getTimeoutPeriod(), 
                                                    env->getProbeRegulatingPeriod(), 
                                                    lbii, 
                                                    ubii, 
                                                    lbis, 
                                                    ubis, 
                                                    env->debugMode());
        }
        else
        {
            prober = new DirectICMPProber(env->getAttentionMessage(), 
                                          env->getTimeoutPeriod(), 
                                          env->getProbeRegulatingPeriod(), 
                                          lbii, 
                                          ubii, 
                                          lbis, 
                                          ubis, 
                                          env->debugMode());
        }
    }
    catch(SocketException &se)
    {
        ostream *out = env->getOutputStream();
        ToolEnvironment::consoleMessagesMutex.lock();
        (*out) << "Caught an exception because no new socket could be opened." << endl;
        ToolEnvironment::consoleMessagesMutex.unlock();
        this->stop();
        throw;
    }
    
    // Gets target IP in the dictionnary, creates it if missing
    targetIP = env->getIPTable()->lookUp(t);
    if(targetIP == NULL)
    {
        targetIP = env->getIPTable()->create(t);
        targetIP->setPreferredTimeout(env->getTimeoutPeriod());
    }
    
    // Verbosity/debug stuff
    displayFinalRoute = false; // Default
    debugMode = false; // Default
    unsigned short displayMode = env->getDisplayMode();
    if(displayMode >= ToolEnvironment::DISPLAY_MODE_SLIGHTLY_VERBOSE)
        displayFinalRoute = true;
    if(displayMode >= ToolEnvironment::DISPLAY_MODE_DEBUG)
        debugMode = true;
    
    // Start of the new log with first probing details (debug mode only)
    if(debugMode)
    {
        stringstream ss;
        ss <<  "Computing route to " << (InetAddress) (*targetIP) << "...\n";
        ss << prober->getAndClearLog();
        
        this->log += ss.str();
    }
}

ParisTracerouteTask::~ParisTracerouteTask()
{
    if(prober != NULL)
    {
        env->updateProbeAmounts(prober);
        delete prober;
    }
}

ProbeRecord *ParisTracerouteTask::probe(const InetAddress &dst, unsigned char TTL)
{
    InetAddress localIP = env->getLocalIPAddress();
    ProbeRecord *record = NULL;
    
    try
    {
        record = prober->singleProbe(localIP, dst, TTL, true);
    }
    catch(SocketException &se)
    {
        throw;
    }
    
    // Debug log
    if(debugMode)
    {
        this->log += prober->getAndClearLog();
    }
    
    /*
     * N.B.: Fixed flow is ALWAYS used in this case, otherwise this is regular Traceroute and not 
     * "Paris" Traceroute.
     */

    return record;
}

void ParisTracerouteTask::stop()
{
    ToolEnvironment::emergencyStopMutex.lock();
    env->triggerStop();
    ToolEnvironment::emergencyStopMutex.unlock();
}

void ParisTracerouteTask::run()
{
    InetAddress probeDst((InetAddress) (*targetIP));

    // probeTTL or probeDst could not be properly found: quits
    if(probeDst == InetAddress(0))
    {
        return;
    }
    
    // Changes timeout if necessary for this IP
    IPLookUpTable *table = env->getIPTable();
    IPTableEntry *probeDstEntry = table->lookUp(probeDst);
    TimeVal usedTimeout = prober->getTimeout();
    if(probeDstEntry != NULL)
    {
        TimeVal preferredTimeout = probeDstEntry->getPreferredTimeout();
        if(preferredTimeout > usedTimeout)
        {
            prober->setTimeout(preferredTimeout);
            usedTimeout = preferredTimeout;
        }
    }
    
    bool reachedDst = false;
    unsigned char probeTTL = 1;
    list<InetAddress> routeHops;
    list<unsigned char> replyTTLs;
    unsigned short anonymous = 0, cycles = 0;
    while(probeTTL <= MAX_TTL)
    {
        ProbeRecord *record = NULL;
        try
        {
            record = this->probe(probeDst, probeTTL);
        }
        catch(SocketException &se)
        {
            this->stop();
            return;
        }
        
        InetAddress rplyAddress = record->getRplyAddress();
        unsigned char remainingTTL = record->getRplyTTL();
        if(rplyAddress == InetAddress(0))
        {
            delete record;
            
            // Debug message
            if(debugMode)
            {
                this->log += "Retrying at this TTL with twice the initial timeout...\n";
            }
            
            // New probe with twice the timeout period
            prober->setTimeout(usedTimeout * 2);
            
            try
            {
                record = this->probe(probeDst, probeTTL);
            }
            catch(SocketException &se)
            {
                this->stop();
                return;
            }
            
            rplyAddress = record->getRplyAddress();
            
            // Restores default timeout
            prober->setTimeout(usedTimeout);
            
            /*
             * N.B.: because this program is supposed to run traceroute more intensively than 
             * TreeNET, there is no 3rd attempt with 4 times the initial timeout.
             */
        }
        
        // Counting consecutive anonymous hops and cycles
        if(rplyAddress == InetAddress(0))
        {
            anonymous++;
        }
        else
        {
            anonymous = 0;
            for(list<InetAddress>::iterator it = routeHops.begin(); it != routeHops.end(); ++it)
            {
                if((*it) == rplyAddress)
                {
                    cycles++;
                    break;
                }
            }
        }
        
        // Scenarii where we should stop
        if(anonymous > env->getMaxConsecutiveAnonHops() || cycles > env->getMaxCycles())
        {
            delete record;
            break;
        }
        
        if(record->getRplyICMPtype() == DirectProber::ICMP_TYPE_DESTINATION_UNREACHABLE)
        {
            delete record;
            break;
        }
        
        if(record->getRplyICMPtype() == DirectProber::ICMP_TYPE_ECHO_REPLY)
        {
            reachedDst = true;
            delete record;
            break;
        }
        
        routeHops.push_back(rplyAddress);
        replyTTLs.push_back(remainingTTL);
        delete record;
        probeTTL++;
    }
    
    // Route array
    unsigned short sizeRoute = (unsigned short) routeHops.size();
    RouteInterface *route = new RouteInterface[sizeRoute];
    unsigned short i = 0;
    for(list<InetAddress>::iterator it = routeHops.begin(); it != routeHops.end(); ++it)
    {
        route[i].ip = (*it);
        if((*it) != InetAddress(0))
            route[i].state = RouteInterface::VIA_TRACEROUTE;
        else
            route[i].state = RouteInterface::MISSING;
        i++;
    }
    
    // Setting inferred initial TTL to each route step
    i = 0;
    for(list<unsigned char>::iterator it = replyTTLs.begin(); it != replyTTLs.end(); ++it)
    {
        unsigned short replyTTLAsShort = (unsigned short) (*it);
        
        if(replyTTLAsShort > 128)
            route[i].iTTL = (unsigned char) 255;
        else if(replyTTLAsShort > 64)
            route[i].iTTL = (unsigned char) 128;
        else if(replyTTLAsShort > 32)
            route[i].iTTL = (unsigned char) 64;
        else if(replyTTLAsShort > 0)
            route[i].iTTL = (unsigned char) 32;
        else
            route[i].iTTL = (unsigned char) 0; // Can happen, though this is rare
        
        i++;
    }
    
    // Recording results in data structures
    Trace *newTrace = new Trace(probeDst);
    if(reachedDst)
    {
        newTrace->setTargetAsReachable();
        targetIP->setTTL(probeTTL);
    }
    newTrace->setRouteSize(sizeRoute);
    newTrace->setRoute(route);
    
    ToolEnvironment::tracesListMutex.lock();
    env->addTrace(newTrace);
    ToolEnvironment::tracesListMutex.unlock();
    
    // Appends the log with a single line (laconic mode) or the route that was obtained
    if(displayFinalRoute)
    {
        stringstream routeLog;
        
        // Adding a line break after probe logs to separate from the complete route
        if(debugMode)
        {
            routeLog << "\n";
        }
        
        routeLog << "Got the route to " << (InetAddress) (*targetIP) << ":\n";
        for(unsigned short i = 0; i < sizeRoute; i++)
        {
            if(route[i].state == RouteInterface::MISSING)
                routeLog << "Missing\n";
            else
                routeLog << route[i].ip << "\n";
        }

        this->log += routeLog.str();
    }
    else
    {
        stringstream routeLog;
        routeLog << "Got the route to " << (InetAddress) (*targetIP) << ".";
        
        this->log += routeLog.str();
    }
    
    // Displays the log, which can be a complete sequence of probe as well as a single line
    ToolEnvironment::consoleMessagesMutex.lock();
    ostream *out = env->getOutputStream();
    (*out) << this->log << endl;
    ToolEnvironment::consoleMessagesMutex.unlock();
}
