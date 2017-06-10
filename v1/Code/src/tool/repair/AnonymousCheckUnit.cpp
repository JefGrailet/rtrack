/*
 * AnonymousCheckUnit.cpp
 *
 *  Created on: May 3, 2017
 *      Author: jefgrailet
 *
 * Implements the class defined in AnonymousCheckUnit.h (see this file to learn further about the 
 * goals of such class).
 */

#include "AnonymousCheckUnit.h"
#include "../../common/thread/Thread.h" // For sleep method

Mutex AnonymousCheckUnit::parentMutex(Mutex::ERROR_CHECKING_MUTEX);

AnonymousCheckUnit::AnonymousCheckUnit(ToolEnvironment *e, 
                                       AnonymousChecker *aC, 
                                       list<Trace*> tR, 
                                       unsigned short lbii, 
                                       unsigned short ubii, 
                                       unsigned short lbis, 
                                       unsigned short ubis) throw(SocketException):
env(e), 
parent(aC), 
toReprobe(tR)
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
    
    if(env->debugMode())
    {
        ToolEnvironment::consoleMessagesMutex.lock();
        ostream *out = env->getOutputStream();
        (*out) << prober->getAndClearLog();
        ToolEnvironment::consoleMessagesMutex.unlock();
    }
}

AnonymousCheckUnit::~AnonymousCheckUnit()
{
    if(prober != NULL)
    {
        env->updateProbeAmounts(prober);
        delete prober;
    }
}

ProbeRecord *AnonymousCheckUnit::probe(const InetAddress &dst, unsigned char TTL)
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
    if(env->debugMode())
    {
        ToolEnvironment::consoleMessagesMutex.lock();
        ostream *out = env->getOutputStream();
        (*out) << prober->getAndClearLog();
        ToolEnvironment::consoleMessagesMutex.unlock();
    }

    return record;
}

void AnonymousCheckUnit::stop()
{
    ToolEnvironment::emergencyStopMutex.lock();
    env->triggerStop();
    ToolEnvironment::emergencyStopMutex.unlock();
}

void AnonymousCheckUnit::run()
{
    for(list<Trace*>::iterator it = toReprobe.begin(); it != toReprobe.end(); ++it)
    {
        Trace *curTrace = (*it);
        
        unsigned short routeSize = curTrace->getRouteSize();
        RouteInterface *route = curTrace->getRoute();
        
        for(unsigned short i = 0; i < routeSize; i++)
        {
            if(route[i].ip != InetAddress(0))
                continue;
        
            ProbeRecord *probeRecord = NULL;
            try
            {
                probeRecord = probe(curTrace->getTargetIP(), (unsigned char) i + 1);
            }
            catch(SocketException &se)
            {
                this->stop();
                return;
            }
            
            if(probeRecord == NULL)
            {
                Thread::invokeSleep(TimeVal(1, 0)); // Default timeout being 1s, we keep a rate of max. 0,5 probe/s
                continue;
            }
            
            unsigned char replyType = probeRecord->getRplyICMPtype();
            if(!probeRecord->isAnonymousRecord() && replyType == DirectProber::ICMP_TYPE_TIME_EXCEEDED)
            {
                parentMutex.lock();
                parent->callback(curTrace, i, probeRecord->getRplyAddress());
                parentMutex.unlock();
                
                Thread::invokeSleep(TimeVal(2, 0));
            }
            
            delete probeRecord;
            
            if(env->isStopping())
                return;
        }
    }
}
