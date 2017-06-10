/*
 * ProbeUnit.cpp
 *
 *  Created on: May 10, 2017
 *      Author: jefgrailet
 *
 * Implements the class defined in ProbeUnit.h (see this file to learn further about the goals of 
 * such class).
 */

#include "ProbeUnit.h"

Mutex ProbeUnit::schedulerMutex(Mutex::ERROR_CHECKING_MUTEX);

ProbeUnit::ProbeUnit(ToolEnvironment *e, 
                     RoundScheduler *p, 
                     InetAddress t, 
                     unsigned char TTL, 
                     unsigned short lbii, 
                     unsigned short ubii, 
                     unsigned short lbis, 
                     unsigned short ubis) throw(SocketException):
env(e), 
parent(p), 
target(t), 
TTL(TTL)
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

ProbeUnit::~ProbeUnit()
{
    if(prober != NULL)
    {
        env->updateProbeAmounts(prober);
        delete prober;
    }
}

void ProbeUnit::stop()
{
    ToolEnvironment::emergencyStopMutex.lock();
    env->triggerStop();
    ToolEnvironment::emergencyStopMutex.unlock();
}

void ProbeUnit::run()
{
    InetAddress localIP = env->getLocalIPAddress();
    ProbeRecord *probeRecord = NULL;
    
    try
    {
        probeRecord = prober->singleProbe(localIP, target, TTL, true);
        
        if(env->debugMode())
        {
            ToolEnvironment::consoleMessagesMutex.lock();
            ostream *out = env->getOutputStream();
            (*out) << prober->getAndClearLog();
            ToolEnvironment::consoleMessagesMutex.unlock();
        }
    }
    catch(SocketException &se)
    {
        this->stop();
        return;
    }
    
    InetAddress replyingIP = probeRecord->getRplyAddress();
    unsigned char replyType = probeRecord->getRplyICMPtype();
    
    if(replyType == DirectProber::ICMP_TYPE_TIME_EXCEEDED)
    {
        schedulerMutex.lock();
        parent->callback(replyingIP);
        schedulerMutex.unlock();
    }
    
    delete probeRecord;
}
