/*
 * TargetParser.cpp
 *
 *  Created on: Oct 2, 2015
 *      Author: jefgrailet
 *
 * Implements the class defined in TargetParser.h.
 */

#include <cstdlib>
#include <algorithm>
#include <sstream>
#include <vector>
#include <fstream>

#include "TargetParser.h"

TargetParser::TargetParser(ToolEnvironment *env)
{
    this->env = env;
}

TargetParser::~TargetParser()
{
}

void TargetParser::parse(string input, char separator)
{
    if(input.size() == 0)
    {
        return;
    }
    
    std::stringstream ss(input);
    std::string targetStr;
    while (std::getline(ss, targetStr, separator))
    {
        // Ignore too small strings
        if (targetStr.size() < MIN_LENGTH_TARGET_STR)
            continue;
    
        size_t pos = targetStr.find('/');
        // Target is a single IP
        if(pos == std::string::npos)
        {
            InetAddress target;
            try
            {
                target.setInetAddress(targetStr);
                parsedIPs.push_back(target);
            }
            catch (InetAddressException &e)
            {
                ostream *out = env->getOutputStream();
                (*out) << "Malformed/Unrecognized destination IP address or host name \"" + targetStr + "\"" << endl;
                continue;
            }
        }
        // Target is a whole address block
        else
        {
            std::string prefix = targetStr.substr(0, pos);
            unsigned char prefixLength = (unsigned char) std::atoi(targetStr.substr(pos + 1).c_str());
            try
            {
                InetAddress blockPrefix(prefix);
                NetworkAddress block(blockPrefix, prefixLength);
                parsedIPBlocks.push_back(block);
            }
            catch (InetAddressException &e)
            {
                ostream *out = env->getOutputStream();
                (*out) << "Malformed/Unrecognized address block \"" + targetStr + "\"" << endl;
                continue;
            }
        }
    }
}

void TargetParser::parseCommandLine(string targetListStr)
{
    std::stringstream ss(targetListStr);
    std::string targetStr;
    std::string plainTargetsStr = "";
    bool first = true;
    while (std::getline(ss, targetStr, ','))
    {
        // Tests if this is some file
        std::ifstream inFile;
        inFile.open(targetStr.c_str());
        
        if(inFile.is_open())
        {
            // Parses the input file
            string inputFileContent = "";
            inputFileContent.assign((std::istreambuf_iterator<char>(inFile)),
                                    (std::istreambuf_iterator<char>()));
            
            parse(inputFileContent, '\n');
        }
        else
        {
            if(first)
                first = false;
            else
                plainTargetsStr += ',';
        
            plainTargetsStr += targetStr;
        }
    }

    // Parses remaining (and plain) targets
    parse(plainTargetsStr, ',');
}

list<InetAddress> TargetParser::reorder(list<InetAddress> toReorder)
{
    unsigned long nbTargets = (unsigned long) toReorder.size();
    unsigned short maxThreads = env->getMaxThreads();
    list<InetAddress> reordered;
    
    // If there are more targets than the amount of threads which will be used
    if(nbTargets > (unsigned long) maxThreads)
    {
        /*
         * TARGET REORDERING
         *
         * As targets are usually given in order, probing consecutive targets may be 
         * inefficient as targetted interfaces may not be as responsive if multiple 
         * threads probe them at the same time (because of the traffic generated at a 
         * time), making inference results less complete and accurate. To avoid this, the 
         * list of targets is re-organized to avoid consecutive IPs as much as possible.
         */
        
        list<InetAddress>::iterator it = toReorder.begin();
        for(unsigned long i = 0; i < nbTargets; i++)
        {
            reordered.push_back((*it));
            toReorder.erase(it--);

            for(unsigned short j = 0; j < maxThreads; j++)
            {
                it++;
                if(it == toReorder.end())
                    it = toReorder.begin();
            }
        }
    }
    else
    {
        // In this case, we will just shuffle the list.
        std::vector<InetAddress> targetsV(toReorder.size());
        std::copy(toReorder.begin(), toReorder.end(), targetsV.begin());
        std::random_shuffle(targetsV.begin(), targetsV.end());
        std::list<InetAddress> shuffledTargets(targetsV.begin(), targetsV.end());
        reordered = shuffledTargets;
    }
    
    return reordered;
}

list<InetAddress> TargetParser::getInitialTargets()
{
    NetworkAddress LAN = env->getLAN();
    InetAddress LANLowerBorder = LAN.getLowerBorderAddress();
    InetAddress LANUpperBorder = LAN.getUpperBorderAddress();
    list<InetAddress> targets;
    
    for(std::list<InetAddress>::iterator it = parsedIPs.begin(); it != parsedIPs.end(); ++it)
    {
        InetAddress target((*it));
        
        if(target >= LANLowerBorder && target <= LANUpperBorder)
            continue;
        
        targets.push_back(target);
    }
    
    for(std::list<NetworkAddress>::iterator it = parsedIPBlocks.begin(); it != parsedIPBlocks.end(); ++it)
    {
        NetworkAddress cur = (*it);
        
        InetAddress lowerBorder = cur.getLowerBorderAddress();
        InetAddress upperBorder = cur.getUpperBorderAddress();

        for(InetAddress cur2 = lowerBorder; cur2 <= upperBorder; cur2++)
        {
            if(cur2 >= LANLowerBorder && cur2 <= LANUpperBorder)
                continue;
            
            targets.push_back(cur2);
        }
    }

    return reorder(targets);
}

list<InetAddress> TargetParser::getResponsiveTargets()
{
    // Starting with all the initial targets, all unresponsive targets are filtered out
    list<InetAddress> initial = this->getInitialTargets();
    list<InetAddress> targets;
    
    IPLookUpTable *table = env->getIPTable();
    
    for(std::list<InetAddress>::iterator it = initial.begin(); it != initial.end(); ++it)
    {
        InetAddress cur = (*it);
        
        if(table->lookUp(cur) != NULL)
        {
            targets.push_back(cur);
        }
    }
    
    return reorder(targets);
}

bool TargetParser::targetsEncompassLAN()
{
    InetAddress localIP = env->getLocalIPAddress();
    
    for(std::list<InetAddress>::iterator it = parsedIPs.begin(); it != parsedIPs.end(); ++it)
    {
        if((*it) == localIP)
            return true;
    }
    
    for(std::list<NetworkAddress>::iterator it = parsedIPBlocks.begin(); it != parsedIPBlocks.end(); ++it)
    {
        NetworkAddress cur = (*it);
        
        InetAddress lowerBorder = cur.getLowerBorderAddress();
        InetAddress upperBorder = cur.getUpperBorderAddress();

        for(InetAddress cur = lowerBorder; cur <= upperBorder; cur++)
        {
            if(cur == localIP)
                return true;
        }
    }
    
    return false;
}
