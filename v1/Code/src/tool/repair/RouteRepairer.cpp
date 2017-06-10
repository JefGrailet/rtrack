/*
 * RouteRepairer.cpp
 *
 *  Created on: May 3, 2017
 *      Author: jefgrailet
 *
 * Implements the class defined in RouteRepairer.h (see this file to learn further about the goals 
 * of such class).
 */

#include "RouteRepairer.h"
#include "AnonymousChecker.h"
#include "../../common/thread/Thread.h"

RouteRepairer::RouteRepairer(ToolEnvironment *env)
{
    this->env = env;
}

RouteRepairer::~RouteRepairer()
{
}

void RouteRepairer::repair()
{
    ostream *out = env->getOutputStream();
    list<Trace*> *traces = env->getTraces();

    /*
     * ROUTE REPAIR
     * 
     * Because of security policies, there are several possibilities of getting an incomplete 
     * route. A route is said to be incomplete when one or several hops (consecutive or not) 
     * could not be obtained because of a timeout (note: the code let also the possibility that 
     * the reply gives 0.0.0.0 as replying interface, though this is unlikely). Timeouts in this 
     * context can be caused by:
     * -permanently "anonymous" routers (routers that route packets, but drop packets when TTL 
     *  expires without a reply), 
     * -a router already identified via previous traceroute and which stops replying after a 
     *  certain rate of probes, 
     * -a firewall which does the same, more or less.
     *
     * For the sake of getting a network mapping as complete as possible, one might wish to 
     * mitigate such issues as much as possible. Therefore:
     * 1) the code first checks if there are traces (i.e., a target IP with a route traced towards 
     *    it) with missing/anonymous hops at all.
     * 2) then, it checks if there are any "unavoidable" missing hop. For instance, if the third 
     *    step of all routes (min. length = 9, for instance) is 0.0.0.0, this cannot be fixed.
     *    These steps are then replaced by placeholders IPs from 0.0.0.0/24 to continue.
     * 3) the code performs offline repair, i.e., for each missing interface, it looks for a 
     *    similar route (i.e., a route where the hops just before and after are identical) or 
     *    checks what is the typical interface at the same amount of hops. When there is one and 
     *    only one possibility, the missing hop is replaced by the typical interface. This method 
     *    is nicknamed "policemen and drunkard" technique.
     * 4) if there remains missing interfaces, the code reprobes at the right TTL each route 
     *    target for each incomplete route. A delay of one minute is left between each reprobing 
     *    and the operation is carried out 3 times.
     * 
     * The process stops once there are no longer incomplete routes (besides unavoidable anonymous 
     * hops), so not all steps mentioned above will necessarily be conducted. No matter when it 
     * stops, all placeholder IPs are changed back to 0.0.0.0 in the end.
     *
     * An important difference with TreeNET is that only routes towards reachable destinations 
     * are considered for counting incomplete routes. Trying to complete routes towards 
     * unreachable destinations (often ending in several anonymous hops or cycles) is indeed a 
     * waste of time.
     */
    
    // Step 1
    unsigned int nbIncomplete = countIncompleteRoutes();
    if(nbIncomplete == 0)
    {
        (*out) << "All routes to reachable destinations are complete." << endl;
        return;
    }
    
    (*out) << "There are incomplete routes towards reachable IPs." << endl;
    
    // Step 2
    unsigned short minLength = 255;
    for(list<Trace*>::iterator it = traces->begin(); it != traces->end(); ++it)
        if((*it)->getRouteSize() > 0 && (*it)->getRouteSize() < minLength)
            minLength = (*it)->getRouteSize();
    
    unsigned short permanentlyAnonymous = 0;
    for(unsigned short i = 0; i < minLength; i++)
    {
        bool anonymous = true;
        for(list<Trace*>::iterator it = traces->begin(); it != traces->end(); ++it)
        {
            if((*it)->hasValidRoute())
            {
                RouteInterface *routeSs = (*it)->getRoute();
                if(routeSs[i].ip != InetAddress(0))
                {
                    anonymous = false;
                    break;
                }
            }
        }
        
        if(anonymous)
        {
            permanentlyAnonymous++;
            for(list<Trace*>::iterator it = traces->begin(); it != traces->end(); ++it)
            {
                if((*it)->hasValidRoute())
                {
                    RouteInterface *routeSs = (*it)->getRoute();
                    routeSs[i].ip = InetAddress(i);
                }
            }
        }
    }
    
    if(permanentlyAnonymous > 0)
    {
        if(permanentlyAnonymous > 1)
        {
            (*out) << "Found " << permanentlyAnonymous << " unavoidable missing hops. ";
            (*out) << "These hops will be considered as regular interfaces during repair." << endl;
        }
        else
        {
            (*out) << "Found one unavoidable missing hop. This hop will be considered as a ";
            (*out) << "regular interface during repair." << endl;
        }
    }
    
    nbIncomplete = countIncompleteRoutes();
    if(nbIncomplete == 0)
    {
        (*out) << "There is no other missing hop in route(s) towards (a) reachable IP(s). No ";
        (*out) << "repair will occur." << endl;
        this->resetUnavoidableAnonHops();
        return;
    }
    
    // Step 3
    if(nbIncomplete > 1)
    {
        (*out) << "Found " << nbIncomplete << " incomplete routes towards reachable IPs. ";
        (*out) << "Starting offline repair..." << endl;
    }
    else
    {
        (*out) << "Found one incomplete route towards a reachable IP. Starting offline ";
        (*out) << "repair..." << endl;
    }
    
    list<RouteRepair*> *repairs = env->getRouteRepairs();
    for(list<Trace*>::iterator it = traces->begin(); it != traces->end(); ++it)
    {
        Trace *curTrace = (*it);
        if(curTrace->getRoute() != NULL)
        {
            if(curTrace->hasIncompleteRoute())
            {
                list<RouteRepair*> curRes = this->repairRouteOffline(curTrace);
                for(list<RouteRepair*>::iterator it2 = curRes.begin(); it2 != curRes.end(); ++it2)
                    (*out) << (*it2)->toString() << endl;
                repairs->splice(repairs->end(), curRes);
            }
        }
    }
     
    if(repairs->size() == 0)
    {
        (*out) << "Could not fix incomplete routes with offline repair." << endl;
    }
    else
    {
        (*out) << "\n";
        nbIncomplete = countIncompleteRoutes();
        if(nbIncomplete == 0)
        {
            (*out) << "All routes towards reachable IPs are now complete." << endl;
            this->resetUnavoidableAnonHops();
            return;
        }
    }
    
    // Step 4
    if(nbIncomplete > 1)
    {
        (*out) << "There remain " << nbIncomplete << " incomplete routes towards reachable IPs. ";
        (*out) << "Starting online repair..." << endl;
    }
    else
    {
        (*out) << "There remains one incomplete route towards a reachable IP. Starting online ";
        (*out) << "repair..." << endl;
    }
    
    AnonymousChecker *checker = NULL;
    list<RouteRepair*> resultOnline;
    Thread::invokeSleep(TimeVal(60, 0)); // Pause of 1 minute before probing again
    
    try
    {
        checker = new AnonymousChecker(env);
        checker->probe();
        
        float ratioSolved = checker->getRatioSolvedHops();
        
        if(ratioSolved > 40.0)
        {
            (*out) << "Repaired " << ratioSolved << "\% of missing hops.";
            
            if(ratioSolved < 100.0)
            {
                (*out) << " Starting a second opinion..." << endl;
                
                Thread::invokeSleep(TimeVal(60, 0));
                
                checker->reload();
                checker->probe();
            }
            else
                (*out) << endl;
        }
        
        resultOnline = checker->getRepairRecords();
        delete checker;
        checker = NULL;
    }
    catch(StopException &se)
    {
        if(checker != NULL)
        {
            delete checker;
            checker = NULL;
        }
        throw StopException();
    }
    
    if(resultOnline.size() == 0)
    {
        (*out) << "Could not fix incomplete routes towards reachable IPs with online repair." << endl;
    }
    else
    {
        for(list<RouteRepair*>::iterator it = resultOnline.begin(); it != resultOnline.end(); ++it)
            (*out) << (*it)->toString() << endl;
        (*out) << endl;
        repairs->splice(repairs->end(), resultOnline);
        
        nbIncomplete = countIncompleteRoutes();
        if(nbIncomplete == 0)
            (*out) << "All routes towards reachable IPs are now complete." << endl;
    }
    
    this->resetUnavoidableAnonHops();
}

unsigned int RouteRepairer::countIncompleteRoutes()
{
    list<Trace*> *traces = env->getTraces();
    unsigned int nbIncompleteRoutes = 0;
    for(list<Trace*>::iterator it = traces->begin(); it != traces->end(); ++it)
    {
        Trace *curTrace = (*it);
        if(curTrace->isTargetReachable() && curTrace->getRoute() != NULL)
        {
            if(curTrace->hasIncompleteRoute())
                nbIncompleteRoutes++;
        }
    }
    return nbIncompleteRoutes;
}

list<RouteRepair*> RouteRepairer::repairRouteOffline(Trace *t)
{
    unsigned short routeSize = t->getRouteSize();
    RouteInterface *route = t->getRoute();
    list<Trace*> *traces = env->getTraces();
    
    list<RouteRepair*> result;
    
    /*
     * Exceptional case: there is only one hop. In that case, we fix it only if there is a single 
     * option among all routes (except when these routes are incomplete as well).
     */
    
    if(routeSize == 1)
    {
        // Lists other traces with a single-hop route
        list<Trace*> similar;
        for(list<Trace*>::iterator it = traces->begin(); it != traces->end(); ++it)
        {
            Trace *t2 = (*it);
            unsigned short routeSize2 = t2->getRouteSize();
            if(routeSize2 == 1)
            {
                RouteInterface *route2 = t2->getRoute();
                if(route2[0].ip == InetAddress(0))
                    similar.push_back(t2);
            }
        }
    
        // Lists options as first hop
        list<InetAddress> options;
        for(list<Trace*>::iterator it = traces->begin(); it != traces->end(); ++it)
        {
            Trace *t2 = (*it);
            unsigned short routeSize2 = t2->getRouteSize();
            if(routeSize2 > 0)
            {
                RouteInterface *route2 = t2->getRoute();
                options.push_back(route2[0].ip);
            }
        }
        
        // Filtering out duplicates
        unsigned int nbOccurrences = options.size(); // For eventual RouteRepair object
        options.sort(InetAddress::smaller);
        InetAddress prev(0);
        for(list<InetAddress>::iterator it = options.begin(); it != options.end(); ++it)
        {
            if((*it) == prev)
                options.erase(it--);
            else
                prev = (*it);
        }
        
        if(options.size() == 1)
        {
            route[0].repair(options.front());
            
            RouteRepair *repair = new RouteRepair();
            repair->replacement = options.front();
            repair->nOccMissing = similar.size();
            repair->nOccExisting = nbOccurrences;
            repair->repairedTraceExample = t;
            repair->TTL = (unsigned char) 1;
            result.push_back(repair);
            
            for(list<Trace*>::iterator it = similar.begin(); it != similar.end(); ++it)
            {
                Trace *t2 = (*it);
                RouteInterface *route2 = t2->getRoute();
                route2[0].repair(options.front());
            }
        }
    
        return result;
    }
    
    for(unsigned short i = 0; i < routeSize - 1; i++) // We don't fix offline a last hop (risky)
    {
        if(route[i].ip != InetAddress(0))
            continue;
        
        InetAddress hopBefore(0), hopAfter(0);
        if(i > 0)
            hopBefore = route[i - 1].ip;
        hopAfter = route[i + 1].ip;
        
        if((i > 0 && hopBefore == InetAddress(0)) || hopAfter == InetAddress(0))
            continue;
        
        // Lists similar traces featuring the same triplet (we will fix them as well)
        list<Trace*> similar;
        for(list<Trace*>::iterator it = traces->begin(); it != traces->end(); ++it)
        {
            Trace *t2 = (*it);
            unsigned short routeSize2 = t2->getRouteSize();
            if(routeSize2 > i + 1)
            {
                RouteInterface *route2 = t2->getRoute();
                if(route2[i].ip == InetAddress(0))
                {
                    if((i == 0 || hopBefore == route2[i - 1].ip) && hopAfter == route2[i + 1].ip)
                    {
                        similar.push_back(t2);
                    }
                }
            }
        }
        
        // Lists the options for a replacement
        list<InetAddress> options;
        for(list<Trace*>::iterator it = traces->begin(); it != traces->end(); ++it)
        {
            Trace *t2 = (*it);
            unsigned short routeSize2 = t2->getRouteSize();
            if(routeSize2 > i + 1)
            {
                RouteInterface *route2 = t2->getRoute();
                if(route2[i].ip == InetAddress(0))
                    continue;
                if((i == 0 || hopBefore == route2[i - 1].ip) && hopAfter == route2[i + 1].ip)
                    options.push_back(route2[i].ip);
            }
        }
        
        // Filtering out duplicates
        unsigned int nbOccurrences = options.size(); // For eventual RouteRepair object
        options.sort(InetAddress::smaller);
        InetAddress prev(0);
        for(list<InetAddress>::iterator it = options.begin(); it != options.end(); ++it)
        {
            if((*it) == prev)
                options.erase(it--);
            else
                prev = (*it);
        }
        
        // Replaces if and only if there is a single option.
        if(options.size() == 1)
        {
            route[i].repair(options.front());
            
            RouteRepair *repair = new RouteRepair();
            if(hopBefore != InetAddress(0))
                repair->hopBefore = hopBefore;
            repair->hopAfter = hopAfter;
            repair->replacement = options.front();
            repair->nOccMissing = similar.size();
            repair->nOccExisting = nbOccurrences;
            repair->repairedTraceExample = t;
            repair->TTL = (unsigned char) (i + 1);
            result.push_back(repair);
            
            for(list<Trace*>::iterator it = similar.begin(); it != similar.end(); ++it)
            {
                Trace *t2 = (*it);
                RouteInterface *route2 = t2->getRoute();
                route2[i].repair(options.front());
            }
        }
    }
    
    result.sort(RouteRepair::compare);
    return result;
}

void RouteRepairer::resetUnavoidableAnonHops()
{
    list<Trace*> *traces = env->getTraces();
    for(list<Trace*>::iterator it = traces->begin(); it != traces->end(); ++it)
    {
        unsigned short routeSize = (*it)->getRouteSize();
        if(routeSize > 0)
        {
            RouteInterface *route = (*it)->getRoute();
            for(unsigned short i = 0; i < routeSize; ++i)
            {
                if(route[i].ip >= InetAddress(1) && route[i].ip <= InetAddress(255))
                    route[i].ip = InetAddress(0);
            }
        }
    }
}
