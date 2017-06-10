/*
 * FingerprintingUnit.h
 *
 *  Created on: May 12, 2017
 *      Author: jefgrailet
 *
 * This class, inheriting Runnable, probes successively each IP it is given (via a list), with a 
 * very large TTL (at this point, all we want is to known if the IP is responsive) in order to 
 * collect additionnal data on it to produce a fingerprint. Currently, it only makes a single 
 * ICMP Echo request and tries to infer the initial TTL of the Echo reply (if it gets one).
 *
 * The class is very similar to NetworkPrescanningUnit, but has been made unique in case it had to 
 * be extended with other probing methods or more generally data collection mechanisms (e.g., 
 * reverse DNS, much like in TreeNET).
 */

#ifndef FINGERPRINTINGUNIT_H_
#define FINGERPRINTINGUNIT_H_

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
#include "FingerprintMaker.h"

class FingerprintingUnit : public Runnable
{
public:

    static const unsigned char VIRTUALLY_INFINITE_TTL = (unsigned char) 255;

    // Mutual exclusion object used when accessing FingerprintMaker
    static Mutex makerMutex;
    
    // Constructor
    FingerprintingUnit(ToolEnvironment *env, 
                       FingerprintMaker *parent, 
                       std::list<InetAddress> IPsToProbe, 
                       unsigned short lowerBoundICMPid = DirectICMPProber::DEFAULT_LOWER_SRC_PORT_ICMP_ID, 
                       unsigned short upperBoundICMPid = DirectICMPProber::DEFAULT_UPPER_SRC_PORT_ICMP_ID, 
                       unsigned short lowerBoundICMPseq = DirectICMPProber::DEFAULT_LOWER_DST_PORT_ICMP_SEQ, 
                       unsigned short upperBoundICMPseq = DirectICMPProber::DEFAULT_UPPER_DST_PORT_ICMP_SEQ) throw(SocketException);
    
    // Destructor, run method
    ~FingerprintingUnit();
    void run();
    
private:
    
    // Pointer to environment (with prober parameters)
    ToolEnvironment *env;
    
    // Private fields
    FingerprintMaker *parent;
    std::list<InetAddress> IPsToProbe;

    // Prober object and probing methods (no TTL asked, since it is here virtually infinite)
    DirectProber *prober;
    ProbeRecord *probe(const InetAddress &dst);
    
    // "Stop" method (when resources are lacking)
    void stop();

};

#endif /* FINGERPRINTINGUNIT_H_ */
