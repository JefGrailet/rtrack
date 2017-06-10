/*
 * RoundScheduler.cpp
 *
 *  Created on: May 10, 2017
 *      Author: jefgrailet
 *
 * Implements the class defined in RoundScheduler.h (see this file to learn further about the 
 * goals of such class).
 */

#include <ostream>
using std::ostream;
#include <iomanip>
using std::flush;
using std::setprecision;

#include <unistd.h> // For usleep() function
#include <math.h> // For pow()

#include "RoundScheduler.h"
#include "ProbeUnit.h"
#include "../../common/thread/Thread.h"

RoundScheduler::RoundScheduler(ToolEnvironment *env, IPTableEntry *candidate)
{
    this->env = env;
    this->candidate = candidate;
    
    curSuccessfulProbes = 0;
}

RoundScheduler::~RoundScheduler()
{
}


void RoundScheduler::callback(InetAddress replyingIP)
{
    if(replyingIP == (InetAddress) (*candidate))
    {
        curSuccessfulProbes++;
    }
    else if(replyingIP != InetAddress(0))
    {
        curMiscIPs.push_back(replyingIP);
    }
}

void RoundScheduler::start()
{
    ostream (*out) = env->getOutputStream();
    unsigned short maxThreads = env->getMaxThreads();
    unsigned short nbExperiments = env->getRLNbExperiments();
    TimeVal delayExperiments = env->getRLDelayExperiments();
    double minResponseRatio = env->getRLMinResponseRatio();
    
    (*out) << "# Evaluation of rate-limit of " << (InetAddress) (*candidate) << "\n" << endl;
    
    unsigned short roundNumber = 1;
    unsigned short nbThreads = 1;
    while(nbThreads < maxThreads)
    {
        TimeVal delayToWait(1, 0);
        delayToWait /= nbThreads;
        
        (*out) << "Starting round n°" << roundNumber << " (";
        if(nbThreads > 1)
            (*out) << nbThreads << " probes";
        else
            (*out) << "one probe";
        (*out) << ", delay between = " << delayToWait << ")." << endl;
        
        RoundRecord curRound(roundNumber);
        for(unsigned short i = 0; i < nbExperiments; i++)
        {
            if(roundNumber > 1 || i > 0)
            {
                // Delay before next experiment
                Thread::invokeSleep(delayExperiments);
            }
        
            (*out) << "Experiment n°" << (i + 1) << "..." << flush;
            
            // Prepares and launches #nbThreads ProbeUnit threads
            unsigned short range = DirectICMPProber::DEFAULT_UPPER_SRC_PORT_ICMP_ID;
            range -= DirectICMPProber::DEFAULT_LOWER_SRC_PORT_ICMP_ID;
            range /= nbThreads;
            
            Thread **th = new Thread*[nbThreads];
            for(unsigned short i = 0; i < nbThreads; i++)
            {
                Runnable *task = NULL;
                try
                {
                    task = new ProbeUnit(env, 
                                         this, 
                                         candidate->getTargetForRLAnalysis(), 
                                         candidate->getTTLForRLAnalysis(), 
                                         DirectICMPProber::DEFAULT_LOWER_SRC_PORT_ICMP_ID + (i * range), 
                                         DirectICMPProber::DEFAULT_LOWER_SRC_PORT_ICMP_ID + (i * range) + range - 1, 
                                         DirectICMPProber::DEFAULT_LOWER_DST_PORT_ICMP_SEQ, 
                                         DirectICMPProber::DEFAULT_UPPER_DST_PORT_ICMP_SEQ);

                    th[i] = new Thread(task);
                }
                catch(SocketException &se)
                {
                    // Cleaning remaining threads (if any is set)
                    for(unsigned short k = 0; k < nbThreads; k++)
                    {
                        delete th[k];
                        th[k] = NULL;
                    }
                    
                    delete[] th;
                    
                    throw StopException();
                }
                catch(ThreadException &te)
                {
                    ostream *out = env->getOutputStream();
                    (*out) << "Unable to create more threads." << endl;
                        
                    delete task;
                
                    // Cleaning remaining threads (if any is set)
                    for(unsigned short k = 0; k < nbThreads; k++)
                    {
                        delete th[k];
                        th[k] = NULL;
                    }
                    
                    delete[] th;
                    
                    throw StopException();
                }
            }

            // Launches thread(s) then waits for completion
            for(unsigned int i = 0; i < nbThreads; i++)
            {
                th[i]->start();
                Thread::invokeSleep(delayToWait);
            }
            
            for(unsigned int i = 0; i < nbThreads; i++)
            {
                th[i]->join();
                delete th[i];
            }
            
            delete[] th;
            
            // Might happen because of SocketSendException thrown within a unit
            if(env->isStopping())
            {
                throw StopException();
            }
            
            // Computes the ratio of responses for this experiment
            double successRatio = ((double) curSuccessfulProbes / (double) nbThreads) * 100;
            curRound.recordRatio(successRatio);
            for(list<InetAddress>::iterator it = curMiscIPs.begin(); it != curMiscIPs.end(); ++it)
                curRound.recordMiscIP(InetAddress((*it)));
            curMiscIPs.clear();
            curSuccessfulProbes = 0;
            
            (*out) << " " << setprecision(5) << successRatio << "\% of successful probes." << endl;
        }
        
        // Add the round record to the entry of the target IP
        double overallSuccess = curRound.getMean();
        (*out) << "Average success ratio: " << setprecision(5) << overallSuccess << "\%.\n" << endl;
        candidate->pushRoundRecord(curRound);
        
        if(overallSuccess < minResponseRatio)
        {
            (*out) << "Average success rate is now below the minimum success ratio (";
            (*out) << minResponseRatio << "\% of probes). Rate-limit evaluation of ";
            (*out) << (InetAddress) (*candidate) << " stops here.\n" << endl;
            break;
        }
        
        roundNumber++;
        nbThreads = (unsigned short) pow(2.0, (double) roundNumber - 1);
    }
    
    if(nbThreads > maxThreads)
    {
        (*out) << "Reached maximum authorized amount of threads (= " << maxThreads;
        (*out) << "). Rate-limit evaluation of " << (InetAddress) (*candidate);
        (*out) << " stops here.\n" << endl;
    }
}
