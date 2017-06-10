/*
 * AnonymousChecker.cpp
 *
 *  Created on: May 3, 2017
 *      Author: jefgrailet
 *
 * Implements the class defined in AnonymousChecker.h (see this file to learn further about the 
 * goals of such class).
 */

#include "AnonymousChecker.h"
#include "AnonymousCheckUnit.h"
#include "../../common/thread/Thread.h"

AnonymousChecker::AnonymousChecker(ToolEnvironment *env)
{
    this->env = env;
    totalAnonymous = 0;
    
    this->loadTargets();
}

AnonymousChecker::~AnonymousChecker()
{
}

unsigned int AnonymousChecker::getTotalSolved()
{
    if(records.size() == 0)
        return 0;
    
    unsigned int total = 0;
    for(list<RouteRepair*>::iterator it = records.begin(); it != records.end(); ++it)
    {
        RouteRepair *cur = (*it);
        total += cur->nOccMissing;
    }
    return total;
}

double AnonymousChecker::getRatioSolvedHops()
{
    return ((double) this->getTotalSolved() / (double) this->totalAnonymous) * 100;
}

void AnonymousChecker::reload()
{
    totalAnonymous = 0;
    incompleteTraces.clear();
    targets.clear();
    toFixOffline.clear();
    
    this->loadTargets();
}

void AnonymousChecker::callback(Trace *target, unsigned short hop, InetAddress solution)
{
    RouteInterface *route = target->getRoute();
    route[hop].deanonymize(solution);
    
    // Beginning/end of route: stops here, there won't be any offline fix with this hop
    if(hop == 0 || hop == target->getRouteSize() - 1)
    {
        RouteRepair *newRepair = new RouteRepair();
        if(hop > 0)
            newRepair->hopBefore = route[hop - 1].ip;
        else
            newRepair->hopBefore = InetAddress(0);
        if(hop < target->getRouteSize() - 1)
            newRepair->hopAfter = route[hop + 1].ip;
        else
            newRepair->hopAfter = InetAddress(0);
        newRepair->replacement = solution;
        newRepair->online = true;
        newRepair->nOccMissing = 1;
        newRepair->repairedTraceExample = target;
        newRepair->TTL = (unsigned char) (hop + 1);
        records.push_back(newRepair);
        return;
    }
    
    // Checks there are similar routes to fix offline
    map<Trace*, list<Trace*> >::iterator lookUp = toFixOffline.find(target);
    if(lookUp == toFixOffline.end() || lookUp->second.size() == 0)
    {
        RouteRepair *newRepair = new RouteRepair();
        newRepair->hopBefore = route[hop - 1].ip;
        newRepair->hopAfter = route[hop + 1].ip;
        newRepair->replacement = solution;
        newRepair->online = true;
        newRepair->nOccMissing = 1;
        newRepair->repairedTraceExample = target;
        newRepair->TTL = (unsigned char) (hop + 1);
        records.push_back(newRepair);
        return;
    }
    
    // Starts fixing (offline) the similar routes
    list<Trace*> routesToFix = lookUp->second;
    for(list<Trace*>::iterator it = routesToFix.begin(); it != routesToFix.end(); ++it)
    {
        Trace *curTrace = (*it);
        
        unsigned short curRouteSize = curTrace->getRouteSize();
        RouteInterface *curRoute = curTrace->getRoute();
        
        // Bunch of verifications, for security
        if(hop >= (curRouteSize - 1) || hop == 0)
            continue;
        
        if(route[hop - 1].ip != curRoute[hop - 1].ip || route[hop + 1].ip != curRoute[hop + 1].ip)
            continue;
        
        if(curRoute[hop].ip != InetAddress(0))
            continue;
        
        curRoute[hop].repairBis(solution);
    }
    
    RouteRepair *newRepair = new RouteRepair();
    newRepair->hopBefore = route[hop - 1].ip;
    newRepair->hopAfter = route[hop + 1].ip;
    newRepair->replacement = solution;
    newRepair->online = true;
    newRepair->nOccMissing = routesToFix.size() + 1;
    newRepair->repairedTraceExample = target;
    newRepair->TTL = (unsigned char) (hop + 1);
    records.push_back(newRepair);
}

void AnonymousChecker::probe()
{
    unsigned short maxThreads = env->getMaxThreads();
    unsigned int nbTargets = this->totalAnonymous;
    
    if(maxThreads > MAX_THREADS)
        maxThreads = MAX_THREADS;
    
    if(nbTargets == 0)
        return;
    
    // N.B.: ideally, we want this phase to last approx. max. one hour.
    unsigned short nbThreads = MIN_THREADS;
    unsigned int targetsPerThread = THREAD_PROBES_PER_HOUR;
    
    if(nbTargets > targetsPerThread && (nbTargets / targetsPerThread) > MIN_THREADS)
        nbThreads = (unsigned short) (nbTargets / targetsPerThread);
    
    if(nbThreads > maxThreads)
        nbThreads = maxThreads;
    
    targetsPerThread = nbTargets / (unsigned int) nbThreads;
    if(targetsPerThread == 0)
        targetsPerThread = 1;
    
    // Computes the list of targets now
    list<list<Trace*> > targetsSets;
    while(this->targets.size() > 0)
    {
        list<Trace*> curList;
        unsigned int curNbTargets = 0;
        while(curNbTargets < targetsPerThread && this->targets.size() > 0)
        {
            Trace *front = this->targets.front();
            this->targets.pop_front();
            
            curNbTargets += front->countMissingHops();
            curList.push_back(front);
        }
        
        if(curList.size() > 0)
            targetsSets.push_back(curList);
    }
    
    unsigned short trueNbThreads = (unsigned short) targetsSets.size();
    
    // Prepares and launches threads
    unsigned short range = (DirectICMPProber::DEFAULT_UPPER_SRC_PORT_ICMP_ID - DirectICMPProber::DEFAULT_LOWER_SRC_PORT_ICMP_ID) / trueNbThreads;
    Thread **th = new Thread*[trueNbThreads];
    
    for(unsigned short i = 0; i < trueNbThreads; i++)
    {
        list<Trace*> targetsSubset = targetsSets.front();
        targetsSets.pop_front();

        Runnable *task = NULL;
        try
        {
            task = new AnonymousCheckUnit(env, 
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
            for(unsigned short k = 0; k < trueNbThreads; k++)
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
            for(unsigned short k = 0; k < trueNbThreads; k++)
            {
                delete th[k];
                th[k] = NULL;
            }
            
            delete[] th;
            
            throw StopException();
        }
    }

    // Launches thread(s) then waits for completion
    for(unsigned int i = 0; i < trueNbThreads; i++)
    {
        th[i]->start();
        Thread::invokeSleep(env->getProbeThreadDelay());
    }
    
    for(unsigned int i = 0; i < trueNbThreads; i++)
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

// Implementation of private methods.

bool AnonymousChecker::similarAnonymousHops(Trace *t1, Trace *t2)
{
    unsigned short sizeRouteT1 = t1->getRouteSize();
    unsigned short sizeRouteT2 = t2->getRouteSize();
    RouteInterface *routeT1 = t1->getRoute();
    RouteInterface *routeT2 = t2->getRoute();
    for(unsigned short i = 1; i < sizeRouteT1 - 1; i++) // We don't fix offline first/last hop (risky)
    {
        if(i >= sizeRouteT2 - 1)
            break;
        
        if(routeT1[i].ip == InetAddress(0))
        {
            InetAddress hopBefore = routeT1[i - 1].ip;
            InetAddress hopAfter = routeT1[i + 1].ip;
            
            if(hopBefore == InetAddress(0) || hopAfter == InetAddress(0))
                continue;
            
            if(routeT2[i - 1].ip == hopBefore && routeT2[i + 1].ip == hopAfter)
                return true;
        }
    }
    return false;
}

void AnonymousChecker::loadTargets()
{
    // Lists incomplete routes
    list<Trace*> sparseRoutes;
    list<Trace*> *fullList = this->env->getTraces();
    for(list<Trace*>::iterator it = fullList->begin(); it != fullList->end(); it++)
    {
        Trace *cur = (*it);
        
        if(cur->isTargetReachable() && cur->hasValidRoute() && cur->hasIncompleteRoute())
        {
            sparseRoutes.push_back(cur);
            this->incompleteTraces.push_back(cur);
            this->totalAnonymous += cur->countMissingHops();
        }
    }
    
    for(list<Trace*>::iterator it = sparseRoutes.begin(); it != sparseRoutes.end(); ++it)
    {
        Trace *cur = (*it);
        this->targets.push_back(cur);
        
        // Lists routes which have similar missing steps
        list<Trace*> similar;
        list<Trace*>::iterator start = it;
        for(list<Trace*>::iterator it2 = ++start; it2 != sparseRoutes.end(); ++it2)
        {
            Trace *cur2 = (*it2);
            if(similarAnonymousHops(cur, cur2))
            {
                similar.push_back(cur2);
                sparseRoutes.erase(it2--);
            }
        }
        
        this->toFixOffline.insert(pair<Trace*, list<Trace*> >(cur, similar));
    }
}
