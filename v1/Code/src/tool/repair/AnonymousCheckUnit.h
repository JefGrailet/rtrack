/*
 * AnonymousCheckUnit.h
 *
 *  Created on: May 3, 2017
 *      Author: jefgrailet
 *
 * This class, inheriting Runnable, probes a target IP used to get a trace with the amount of hops 
 * corresponding to a missing hop (which is either truly anonymous, either "temporarily" anonymous 
 * because of security measures, like rate-limiting policies) in order to confirm if this hop is 
 * really anonymous.
 *
 * As there can be several missing hops in a trace, this class will use the right TTLs for each 
 * and therefore probe the same target IP several times. When a reply is obtained, it calls back 
 * the parent AnonymousChecker object to perform the trace fix (plus propagation in similar 
 * traces).
 *
 * This class comes almost straight out of TreeNET (implemented initially mid-February 2017), with 
 * some minor modifications since we are no longer handling subnets but only traces.
 */

#ifndef ANONYMOUSCHECKUNIT_H_
#define ANONYMOUSCHECKUNIT_H_

#include <list>
using std::list;

#include "AnonymousChecker.h"
#include "../../common/thread/Runnable.h"
#include "../../prober/DirectProber.h"
#include "../../prober/icmp/DirectICMPProber.h"
#include "../../prober/udp/DirectUDPWrappedICMPProber.h"
#include "../../prober/tcp/DirectTCPWrappedICMPProber.h"
#include "../../prober/exception/SocketException.h"
#include "../../prober/structure/ProbeRecord.h"

class AnonymousCheckUnit : public Runnable
{
public:

    // Mutual exclusion object used when accessing AnonymousChecker
    static Mutex parentMutex;
    
    // Constructor
    AnonymousCheckUnit(ToolEnvironment *env, 
                       AnonymousChecker *parent, 
                       list<Trace*> toReprobe, 
                       unsigned short lowerBoundICMPid = DirectICMPProber::DEFAULT_LOWER_SRC_PORT_ICMP_ID, 
                       unsigned short upperBoundICMPid = DirectICMPProber::DEFAULT_UPPER_SRC_PORT_ICMP_ID, 
                       unsigned short lowerBoundICMPseq = DirectICMPProber::DEFAULT_LOWER_DST_PORT_ICMP_SEQ, 
                       unsigned short upperBoundICMPseq = DirectICMPProber::DEFAULT_UPPER_DST_PORT_ICMP_SEQ) throw(SocketException);
    
    // Destructor, run method
    ~AnonymousCheckUnit();
    void run();
    
private:
    
    // Pointer to environment (with prober parameters)
    ToolEnvironment *env;
    
    // Private fields
    AnonymousChecker *parent;
    list<Trace*> toReprobe;

    // Prober object and probing methods
    DirectProber *prober;
    ProbeRecord *probe(const InetAddress &dst, unsigned char TTL);
    
    // "Stop" method (when resources are lacking)
    void stop();

};

#endif /* ANONYMOUSCHECKUNIT_H_ */
