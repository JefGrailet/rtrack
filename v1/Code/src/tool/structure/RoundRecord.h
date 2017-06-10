/*
 * RoundRecord.h
 *
 *  Created on: May 9, 2017
 *      Author: jefgrailet
 *
 * This file defines a class "RoundRecord" which is meant to store the ratios of successful probes 
 * recorded for an experiment of a probing round while evaluating the rate-limit of some IP. There 
 * are as many ratios as there are experiments during the round.
 */

#ifndef ROUNDRECORD_H_
#define ROUNDRECORD_H_

#include <list>
using std::list;
#include <string>
using std::string;

#include "../../common/inet/InetAddress.h"

class RoundRecord
{
public:

    // Constructor, destructor
    RoundRecord(unsigned short roundID);
    ~RoundRecord();
    
    inline void recordRatio(double ratio) { ratios.push_back(ratio); }
    inline void recordMiscIP(InetAddress miscIP) { miscIPs.push_back(miscIP); }
    double getMean();
	
	// Outputs the round in human-readable format
    string toString();

private:
    
    unsigned short roundID;
    list<double> ratios;
    list<InetAddress> miscIPs;
    
};

#endif /* ROUNDRECORD_H_ */
