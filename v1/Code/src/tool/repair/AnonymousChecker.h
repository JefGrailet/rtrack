/*
 * AnonymousChecker.h
 *
 *  Created on: May 3, 2017
 *      Author: jefgrailet
 *
 * AnonymousChecker is designed to schedule new probing towards certain target IPs which the 
 * associated trace is incomplete, i.e., there are anonymous hops, or rather steps in the route 
 * where there was a timeout during probing instead of a regular reply. Such anonymous hops can be 
 * caused by several factors:
 * -either the corresponding router is configured to not reply to such probes (pure anonymous 
 *  router), 
 * -either the corresponding router is rate-limited and missing hops can be solved by re-probing 
 *  with careful timing, 
 * -either a firewall dropped the packets to prevent router discovery.
 *
 * Of course, AnonymousChecker aims at "solving" the second case, which can not always be solved 
 * through offline correction as already applied elsewhere in the program. To do so, it carefully 
 * analyzes the current traces to isolate those which require additionnal probing (if several 
 * incomplete routes are similar and could be fixed offline, then only one probe is needed) then 
 * spread the work among several probing threads (see the class AnonymousCheckUnit).
 *
 * This class comes almost straight out of TreeNET (implemented initially mid-February 2017), with 
 * some minor modifications since we are no longer handling subnets but only traces. However, an 
 * important difference with TreeNET is that only routes towards reachable destinations are 
 * considered for censing incomplete routes. Trying to complete routes towards unreachable 
 * destinations (often ending in several anonymous hops or cycles) is indeed a waste of time.
 */

#ifndef ANONYMOUSCHECKER_H_
#define ANONYMOUSCHECKER_H_

#include <map>
using std::map;
using std::pair;

#include "../ToolEnvironment.h"

class AnonymousChecker
{
public:

    const static unsigned int THREAD_PROBES_PER_HOUR = 1800; // Max. of probes per thread/hour
    const static unsigned short MIN_THREADS = 4; // To speed up things for low amount of targets
    const static unsigned short MAX_THREADS = 16; // To avoid being too aggressive, too

    // Constructor, destructor
    AnonymousChecker(ToolEnvironment *env);
    ~AnonymousChecker();
    
    inline unsigned int getTotalAnonymous() { return this->totalAnonymous; }
    inline list<RouteRepair*> getRepairRecords() { return this->records; }
    unsigned int getTotalSolved();
    
    double getRatioSolvedHops(); // To call AFTER probe()
    
    // Callback method (for child threads)
    void callback(Trace *target, unsigned short hop, InetAddress solution);
    
    // Starts the probing
    void probe();
    void reload();
    
private:

    // Pointer to the environment (provides access to the trace set and prober parameters)
    ToolEnvironment *env;
    
    // Total of anonymous hops to (attempt to) solve and records of route repairs
    unsigned int totalAnonymous;
    list<RouteRepair*> records;
    
    /*
     * Two lists: one to list all incomplete traces at loading, and another to list the traces 
     * which are used for the re-probing. Not all incomplete traces are probed again because route 
     * similarities allow offline fix after solving an anonymous hop. Say 3 * traces have the 
     * route steps ..., 1.2.3.4, 0.0.0.0, * 5.6.7.8, ... at the same positions, then only one 
     * should be re-probed with the proper TTL to try to solve the anonymous step.
     */
    
    list<Trace*> incompleteTraces;
    list<Trace*> targets;
    
    /*
     * Following map is used to match a trace with the traces that share route similarities 
     * allowing a offline fix.
     */
    
    map<Trace*, list<Trace*> > toFixOffline;
    
    static bool similarAnonymousHops(Trace *t1, Trace *t2); // True if fit for fix
    void loadTargets(); // Lists targets
    
}; 

#endif /* ANONYMOUSCHECKER_H_ */
