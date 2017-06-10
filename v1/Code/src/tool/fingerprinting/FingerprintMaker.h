/*
 * FingerprintMaker.h
 *
 *  Created on: May 12, 2017
 *      Author: jefgrailet
 *
 * FingerprintMaker is a class meant to schedule probes towards previously discovered IPs in order 
 * to fingerprint them, using FingerprintingUnit to send the probes themselves. The class is very 
 * similar in construction to NetworkPrescanner, but has been made unique because it might be 
 * differentiated further in the future (extended fingerprinting).
 */

#ifndef FINGERPRINTMAKER_H_
#define FINGERPRINTMAKER_H_

#include <list>
using std::list;

#include "../ToolEnvironment.h"

class FingerprintMaker
{
public:

    const static unsigned short MINIMUM_TARGETS_PER_THREAD = 2;

    // Constructor, destructor
    FingerprintMaker(ToolEnvironment *env); // Targets obtained via env
    ~FingerprintMaker();

    // Callback method (for children threads)
    void callback(InetAddress target, unsigned char iTTL);
    
    // Schedules and starts the probing
    void probe();
    
private:

    // Pointer to the environment (provides access to IP dictionnary and the targets)
    ToolEnvironment *env;
    
}; 

#endif /* FINGERPRINTMAKER_H_ */
