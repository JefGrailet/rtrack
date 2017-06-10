/*
 * RouteRepairer.h
 *
 *  Created on: May 3, 2017
 *      Author: jefgrailet
 *
 * This class provides the algorithmic approaches to fix incomplete traces, mostly using the 
 * "policemen and drunkard" approach. I.e., for each triplet of consecutive hops A, *, B, we 
 * look in other traces containing A and B at the same hop counts and check how many possibilities 
 * there are for replacing *. If there is only one, then we can replace the * with this single 
 * possibility.
 *
 * In addition to this offline approach, RouteRepairer also starts the online approach which 
 * consists in reprobing the targets with which incomplete traces were obtained with the right 
 * amount of hops and careful timing to check if the missing hops are just a consequence of 
 * rate-limiting or if they correspond to truly anonymous interfaces.
 *
 * The whole class is essentially a rewritten version of some parts of ClassicGrower in TreeNET 
 * v3.2+ Arborist and Forester, isolated from the rest of the code for the sake of readability.
 */

#ifndef ROUTEREPAIRER_H_
#define ROUTEREPAIRER_H_

#include "../ToolEnvironment.h"

class RouteRepairer
{
public:

    // Constructor, destructor
    RouteRepairer(ToolEnvironment *env);
    ~RouteRepairer();
    
    void repair();
    
private:

    // Pointer to the environment (provides access to the trace set and prober parameters)
    ToolEnvironment *env;
    
    // Method to count the amount of incomplete routes seen in the set of traces.
    unsigned int countIncompleteRoutes();
    
    /*
     * Repairment of a route (see repair()); unlike in TreeNET, it returns a list of pointers to 
     * RouteRepair objects to keep track of all repairment details (relevant for data analysis).
     */
    
    list<RouteRepair*> repairRouteOffline(Trace *t);
    
    // Resets unavoidable anonymous IPs back to 0.0.0.0 rather than an IP from 0.0.0.0/24
    void resetUnavoidableAnonHops();
    
}; 

#endif /* ROUTEREPAIRER_H_ */
