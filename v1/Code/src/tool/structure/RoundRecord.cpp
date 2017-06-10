/*
 * RoundRecord.cpp
 *
 *  Created on: May 9, 2017
 *      Author: jefgrailet
 *
 * Implements the class defined in RoundRecord.h (see this file to learn further about the goals 
 * of such class).
 */

#include <sstream>
using std::stringstream;
#include <iomanip>
using std::setprecision;
#include <math.h> // For pow()

#include "RoundRecord.h"

RoundRecord::RoundRecord(unsigned short roundID)
{
    this->roundID = roundID;
}

RoundRecord::~RoundRecord()
{
}

double RoundRecord::getMean()
{
    double total = 0.0;
    for(list<double>::iterator it = ratios.begin(); it != ratios.end(); ++it)
    {
        total += (*it);
    }
    return total / (double) ratios.size();
}

string RoundRecord::toString()
{
    stringstream ss;
    
    ss << roundID << " - ";
    for(list<double>::iterator it = ratios.begin(); it != ratios.end(); ++it)
    {
        if(it != ratios.begin())
            ss << " ";
        ss << setprecision(6) << (*it);
    }
    
    unsigned int totalProbes = (unsigned int) (pow(2.0, (double) roundID - 1)) * ratios.size();
    miscIPs.sort(InetAddress::smaller);
    if(miscIPs.size() > 0)
    {
        ss << " - Misc IPs: ";
        InetAddress prev = InetAddress(0);
        unsigned int count = 0;
        bool guardian = true;
        for(list<InetAddress>::iterator it = miscIPs.begin(); it != miscIPs.end(); ++it)
        {
            InetAddress cur = (*it);
            if(cur == prev)
            {
                count++;
            }
            else
            {
                if(count > 0)
                {
                    if(guardian)
                        guardian = false;
                    else
                        ss << ", ";
                
                    double ratio = ((double) count / (double) totalProbes) * 100;
                    ss << prev << " (" << setprecision(5) << ratio << "%)";
                }
                
                prev = cur;
                count = 1;
            }
        }
        
        // Last one
        if(guardian)
            guardian = false;
        else
            ss << ", ";
        double ratio = ((double) count / (double) totalProbes) * 100;
        ss << prev << " (" << setprecision(5) << ratio << "%)";
    }
    
    return ss.str();
}
