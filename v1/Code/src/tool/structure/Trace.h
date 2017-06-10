/*
 * Trace.h
 *
 *  Created on: May 3, 2017
 *      Author: jefgrailet
 *
 * Trace class is a simple class made to model a traceroute record as an array of RouteInterface 
 * objects and provide various methods to handle this record, but also the possibility to have a 
 * post-processed equivalent. It is more or less a (very) simplified version of SubnetSite class 
 * in TreeNET v3+ Arborist and Forester.
 *
 * Initially, the route details were in IPTableEntry, but removed and made into a separate class 
 * because most of the IPs in the IP dictionnary would not route fields.
 */

#ifndef TRACE_H_
#define TRACE_H_

#include <string>
using std::string;

#include "RouteInterface.h"

class Trace
{
public:

    // Constructor, destructor
    Trace(InetAddress targetIP);
    ~Trace();
    
    // Accessers/setters
    inline InetAddress getTargetIP() { return this->targetIP; }
    inline bool isTargetReachable() { return this->reachable; }
    inline unsigned short getRouteSize() { return this->routeSize; }
    inline RouteInterface* getRoute() { return this->route; }
    
    inline void setTargetAsReachable() { this->reachable = true; }
    inline void setRouteSize(unsigned short rs) { this->routeSize = rs; }
    inline void setRoute(RouteInterface *r) { this->route = r; }
    inline bool hasValidRoute() { return this->routeSize > 0 && this->route != NULL; }
    inline bool isPostProcessed() { return this->processedRouteSize > 0 && this->processedRoute != NULL; }
    
    // Special field to distinguish the second/third/fourth/... traces from others.
    inline unsigned short getOpinionNumber() { return this->opinionNumber; }
    inline void setOpinionNumber(unsigned short oNb) { this->opinionNumber = oNb; }
    
    // Next methods assume the calling code previously checked there is a valid route.
    bool hasCompleteRoute(); // Returns true if the route has no missing/anonymous hop
    bool hasIncompleteRoute(); // Dual operation (true if the route has missing/anonymous hop)
    unsigned short countMissingHops(); // Returns amount of missing/anonymous hops
    
    bool isStretched();
    bool hasCycles();
    
    // Accessers/setters for the (optional) post-processed route
    inline void setProcessedRouteSize(unsigned short prs) { this->processedRouteSize = prs; }
    inline void setProcessedRoute(RouteInterface *pRoute) { this->processedRoute = pRoute; }
    inline unsigned short getProcessedRouteSize() { return this->processedRouteSize; }
    inline RouteInterface *getProcessedRoute() { return this->processedRoute; }

    // Methods to output the trace (respectively, observed traces and post-processed traces)
    string toStringMeasured();
    string toStringPostProcessed();
    
    // Comparison method for sorting purposes
    static bool compare(Trace *t1, Trace *t2);

private:
    
    InetAddress targetIP; // Target used to obtain this trace
    bool reachable; // True if we eventually got a reply from this IP (e.g. ECHO reply with ICMP)
    unsigned short opinionNumber; // 1 (default) = first trace, 2 = 2nd opinion, etc.
    
    // Observed route
    unsigned short routeSize;
    RouteInterface *route;
    
    // Post-processed route (optional)
    unsigned short processedRouteSize;
    RouteInterface *processedRoute;

};

#endif /* TRACE_H_ */
