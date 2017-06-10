/*
 * ProbeUnit.h
 *
 *  Created on: May 10, 2017
 *      Author: jefgrailet
 *
 * This class, inheriting Runnable, probes once a single IP, typically with an ICMP Echo request 
 * (by default). Its sole purpose is to check if it can get a reply, as it is part of the module 
 * checking the rate-limit of an IP suspected to be rate-limited.
 */

#ifndef PROBEUNIT_H_
#define PROBEUNIT_H_

#include <list>
using std::list;

#include "../ToolEnvironment.h"
#include "../../common/thread/Runnable.h"
#include "../../prober/DirectProber.h"
#include "../../prober/icmp/DirectICMPProber.h"
#include "../../prober/udp/DirectUDPWrappedICMPProber.h"
#include "../../prober/tcp/DirectTCPWrappedICMPProber.h"
#include "../../prober/exception/SocketException.h"
#include "../../prober/structure/ProbeRecord.h"
#include "RoundScheduler.h"

class ProbeUnit : public Runnable
{
public:

    // Mutual exclusion object used when accessing RoundScheduler
    static Mutex schedulerMutex;
    
    // Constructor
    ProbeUnit(ToolEnvironment *env, 
              RoundScheduler *parent, 
              InetAddress target, 
              unsigned char TTL, 
              unsigned short lowerBoundICMPid = DirectICMPProber::DEFAULT_LOWER_SRC_PORT_ICMP_ID, 
              unsigned short upperBoundICMPid = DirectICMPProber::DEFAULT_UPPER_SRC_PORT_ICMP_ID, 
              unsigned short lowerBoundICMPseq = DirectICMPProber::DEFAULT_LOWER_DST_PORT_ICMP_SEQ, 
              unsigned short upperBoundICMPseq = DirectICMPProber::DEFAULT_UPPER_DST_PORT_ICMP_SEQ) throw(SocketException);
    
    // Destructor, run method
    ~ProbeUnit();
    void run();
    
private:
    
    // Pointer to environment (with prober parameters)
    ToolEnvironment *env;
    
    // Private fields
    RoundScheduler *parent;
    InetAddress target;
    unsigned char TTL;

    // Prober object
    DirectProber *prober;
    
    // "Stop" method (when resources are lacking)
    void stop();

};

#endif /* PROBEUNIT_H_ */
