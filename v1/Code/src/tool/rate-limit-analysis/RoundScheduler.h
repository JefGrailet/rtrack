/*
 * RoundScheduler.h
 *
 *  Created on: May 10, 2017
 *      Author: jefgrailet
 *
 * RoundScheduler is the main class of the rate-limit analysis module. The rate-limit analysis 
 * consists here in probing a target IP in several rounds, with an increasing amount of probes 
 * sent in a second (round 1 = one probe/sec., round 2 = 2 probes/sec., ...). At each round, the 
 * experiment is repeated a certain amount of times (fixed by the user, typical value is 15) so 
 * that a third party script can parse the ratio of responses to probes and produce an average and 
 * a confidence interval for each round. The data can then be analyzed empirically.
 * 
 * RoundScheduler schedules the different rounds and their experiments and stops scheduling when: 
 * -the response rate is too low (in average), 
 * -when round number = maximum amount of threads (chosen by the user).
 */

#ifndef ROUNDSCHEDULER_H_
#define ROUNDSCHEDULER_H_

#include "../ToolEnvironment.h"

class RoundScheduler
{
public:

    // Constructor, destructor
    RoundScheduler(ToolEnvironment *env, IPTableEntry *candidate);
    ~RoundScheduler();
    
    // Callback method (for child threads)
    void callback(InetAddress replyingIP);
    
    // Launches the scheduling
    void start();
    
private:

    // Private fields (env for probing parameters and candidate IP for rate-limit analysis)
    ToolEnvironment *env;
    IPTableEntry *candidate;
    
    // RoundRecord object being filled during a round, plus successful experiments
    unsigned int curSuccessfulProbes;
    list<InetAddress> curMiscIPs;
    
}; 

#endif /* ROUNDSCHEDULER_H_ */
