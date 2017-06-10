/*
 * FingerprintMaker.cpp
 *
 *  Created on: May 12, 2017
 *      Author: jefgrailet
 *
 * Implements the class defined in FingerprintMaker.h (see this file to learn further about the 
 * goals of such class).
 */

#include <ostream>
using std::ostream;

#include <unistd.h> // For usleep() function

#include "FingerprintMaker.h"
#include "FingerprintingUnit.h"
#include "../../common/thread/Thread.h"

FingerprintMaker::FingerprintMaker(ToolEnvironment *env)
{
    this->env = env;
}

FingerprintMaker::~FingerprintMaker()
{
}

void FingerprintMaker::callback(InetAddress target, unsigned char iTTL)
{
    if(iTTL == 0)
    {
        return;
    }
    
    IPLookUpTable *table = env->getIPTable();
    IPTableEntry *IPEntry = table->lookUp(target);
    if(IPEntry != NULL)
    {
        IPEntry->setInitialTTLEcho(iTTL);
        
        ostream *out = env->getOutputStream();
        (*out) << IPEntry->toStringFingerprint() << std::flush;
    }
}

void FingerprintMaker::probe()
{
    list<InetAddress> targets = env->getIPTable()->listIPs();
    unsigned short maxThreads = env->getMaxThreads();
    unsigned long nbTargets = (unsigned long) targets.size();
    if(nbTargets == 0)
    {
        return;
    }
    unsigned short nbThreads = 1;
    unsigned long targetsPerThread = (unsigned long) FingerprintMaker::MINIMUM_TARGETS_PER_THREAD;
    unsigned long lastTargets = 0;
    
    // Computes amount of threads and amount of targets being probed per thread
    if(nbTargets > FingerprintMaker::MINIMUM_TARGETS_PER_THREAD)
    {
        if((nbTargets / targetsPerThread) > (unsigned long) maxThreads)
        {
            unsigned long factor = 2;
            while((nbTargets / (targetsPerThread * factor)) > (unsigned long) maxThreads)
                factor++;
            
            targetsPerThread *= factor;
        }
        
        nbThreads = (unsigned short) (nbTargets / targetsPerThread);
        lastTargets = nbTargets % targetsPerThread;
        if(lastTargets > 0)
            nbThreads++;
    }
    else
        lastTargets = nbTargets;

    // Prepares and launches threads
    unsigned short range = (DirectICMPProber::DEFAULT_UPPER_SRC_PORT_ICMP_ID - DirectICMPProber::DEFAULT_LOWER_SRC_PORT_ICMP_ID) / nbThreads;
    Thread **th = new Thread*[nbThreads];
    
    for(unsigned short i = 0; i < nbThreads; i++)
    {
        std::list<InetAddress> targetsSubset;
        unsigned long toRead = targetsPerThread;
        if(lastTargets > 0 && i == (nbThreads - 1))
            toRead = lastTargets;
        
        for(unsigned long j = 0; j < toRead; j++)
        {
            InetAddress addr(targets.front());
            targetsSubset.push_back(addr);
            targets.pop_front();
        }

        Runnable *task = NULL;
        try
        {
            task = new FingerprintingUnit(env, 
                                          this, 
                                          targetsSubset, 
                                          DirectICMPProber::DEFAULT_LOWER_SRC_PORT_ICMP_ID + (i * range), 
                                          DirectICMPProber::DEFAULT_LOWER_SRC_PORT_ICMP_ID + (i * range) + range - 1, 
                                          DirectICMPProber::DEFAULT_LOWER_DST_PORT_ICMP_SEQ, 
                                          DirectICMPProber::DEFAULT_UPPER_DST_PORT_ICMP_SEQ);

            th[i] = new Thread(task);
        }
        catch(SocketException &se)
        {
            // Cleaning remaining threads (if any is set)
            for(unsigned short k = 0; k < nbThreads; k++)
            {
                delete th[k];
                th[k] = NULL;
            }
            
            delete[] th;
            
            throw StopException();
        }
        catch(ThreadException &te)
        {
            ostream *out = env->getOutputStream();
            (*out) << "Unable to create more threads." << endl;
                
            delete task;
        
            // Cleaning remaining threads (if any is set)
            for(unsigned short k = 0; k < nbThreads; k++)
            {
                delete th[k];
                th[k] = NULL;
            }
            
            delete[] th;
            
            throw StopException();
        }
    }

    // Launches thread(s) then waits for completion
    for(unsigned int i = 0; i < nbThreads; i++)
    {
        th[i]->start();
        Thread::invokeSleep(env->getProbeThreadDelay());
    }
    
    for(unsigned int i = 0; i < nbThreads; i++)
    {
        th[i]->join();
        delete th[i];
    }
    
    delete[] th;
    
    // Might happen because of SocketSendException thrown within a unit
    if(env->isStopping())
    {
        throw StopException();
    }
}
