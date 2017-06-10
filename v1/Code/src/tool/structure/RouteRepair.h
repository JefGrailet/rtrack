/*
 * RouteRepair.h
 *
 *  Created on: May 10, 2017
 *      Author: jefgrailet
 *
 * This class models a route repair, i.e.:
 * -a triplet A, *, B (middle of route) or a duo *, A (beginning of route), 
 * -a total of occurrences of A, *, B / *, A, 
 * -a total of occurrences of A, C, B / B, A if it exists and if there is no other solution (e.g., 
 *  another triplet A, D, B).
 * On rare occurrences, it can also model a replacement of a single-hop route * with A if A is the 
 * first hop of all other routes collected at the same time towards a same network.
 */

#ifndef ROUTEREPAIR_H_
#define ROUTEREPAIR_H_

#include <string>
using std::string;

#include "Trace.h"

class RouteRepair
{
public:

    RouteRepair();
    ~RouteRepair();
    
    string toString();
    static bool compare(RouteRepair *rr1, RouteRepair *rr2);
    
    InetAddress hopBefore, hopAfter;
    InetAddress replacement;
    bool online; // Set to true if the repair was obtained due to online repair
    unsigned int nOccMissing; // Occurrences of A, *, B / *, A
    unsigned int nOccExisting; // Occurrences of A, C, B / B, A
    
    Trace *repairedTraceExample; // Example of a trace where the middle IP had to be replaced
    unsigned char TTL; // TTL at which the middle IP appears
    
};

#endif /* ROUTEREPAIRMENT_H_ */
