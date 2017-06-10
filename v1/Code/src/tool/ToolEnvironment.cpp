/*
 * ToolEnvironment.cpp
 *
 *  Created on: May 2, 2017
 *      Author: jefgrailet
 *
 * This file implements the class defined in ToolEnvironment.h. See this file for more details 
 * on the goals of such class.
 */

#include <sys/stat.h> // For CHMOD edition

#include "ToolEnvironment.h"

Mutex ToolEnvironment::tracesListMutex(Mutex::ERROR_CHECKING_MUTEX);
Mutex ToolEnvironment::consoleMessagesMutex(Mutex::ERROR_CHECKING_MUTEX);
Mutex ToolEnvironment::emergencyStopMutex(Mutex::ERROR_CHECKING_MUTEX);

ToolEnvironment::ToolEnvironment(ostream *cOut, 
                                 bool extLogs, 
                                 unsigned short protocol, 
                                 InetAddress &localIP, 
                                 NetworkAddress &lan, 
                                 string &probeMsg, 
                                 TimeVal &timeout, 
                                 TimeVal &regulatingPeriod, 
                                 TimeVal &threadDelay, 
                                 unsigned short mCAH, 
                                 unsigned short mC, 
                                 unsigned short RLExps, 
                                 TimeVal &RLDelay, 
                                 double RLRatio, 
                                 unsigned short dMode, 
                                 unsigned short mT):
consoleOut(cOut), 
externalLogs(extLogs), 
isExternalLogOpened(false), 
probingProtocol(protocol), 
localIPAddress(localIP), 
LAN(lan), 
probeAttentionMessage(probeMsg), 
timeoutPeriod(timeout), 
probeRegulatingPeriod(regulatingPeriod), 
probeThreadDelay(threadDelay), 
maxConsecutiveAnonHops(mCAH), 
maxCycles(mC), 
bisTracesCounter(0), 
RLNbExperiments(RLExps), 
RLDelayExperiments(RLDelay), 
RLMinResponseRatio(RLRatio), 
displayMode(dMode), 
maxThreads(mT), 
totalProbes(0), 
totalSuccessfulProbes(0), 
flagEmergencyStop(false)
{
    this->IPTable = new IPLookUpTable();
}

ToolEnvironment::~ToolEnvironment()
{
    delete IPTable;
    
    for(list<Trace*>::iterator it = traces.begin(); it != traces.end(); it++)
    {
        delete (*it);
    }
    traces.clear();
    
    for(list<RouteRepair*>::iterator it = routeRepairs.begin(); it != routeRepairs.end(); it++)
    {
        delete (*it);
    }
    routeRepairs.clear();
}

void ToolEnvironment::addTrace(Trace *newTrace)
{
    if(bisTracesCounter >= 1)
        newTrace->setOpinionNumber(bisTracesCounter + 1);
    traces.push_back(newTrace);
}

ostream* ToolEnvironment::getOutputStream()
{
    if(this->externalLogs || this->isExternalLogOpened)
        return &this->logStream;
    return this->consoleOut;
}

bool ToolEnvironment::hasPostProcessedTraces()
{
    for(list<Trace*>::iterator it = traces.begin(); it != traces.end(); it++)
        if((*it)->isPostProcessed())
            return true;
    return false;
}

void ToolEnvironment::outputTracesMeasured(string filename)
{
    ofstream newFile;
    newFile.open(filename.c_str());
    for(list<Trace*>::iterator it = traces.begin(); it != traces.end(); it++)
    {
        newFile << (*it)->toStringMeasured();
    }
    newFile.close();
    
    // File must be accessible to all
    string path = "./" + filename;
    chmod(path.c_str(), 0766);
}

void ToolEnvironment::outputTracesPostProcessed(string filename)
{
    ofstream newFile;
    newFile.open(filename.c_str());
    for(list<Trace*>::iterator it = traces.begin(); it != traces.end(); it++)
    {
        newFile << (*it)->toStringPostProcessed();
    }
    newFile.close();
    
    // File must be accessible to all
    string path = "./" + filename;
    chmod(path.c_str(), 0766);
}

void ToolEnvironment::outputRouteRepairs(string filename)
{
    routeRepairs.sort(RouteRepair::compare);

    ofstream newFile;
    newFile.open(filename.c_str());
    for(list<RouteRepair*>::iterator it = routeRepairs.begin(); it != routeRepairs.end(); it++)
    {
        newFile << (*it)->toString() << "\n";
    }
    newFile.close();
    
    // File must be accessible to all
    string path = "./" + filename;
    chmod(path.c_str(), 0766);
}

void ToolEnvironment::updateProbeAmounts(DirectProber *proberObject)
{
    totalProbes += proberObject->getNbProbes();
    totalSuccessfulProbes += proberObject->getNbSuccessfulProbes();
}

void ToolEnvironment::resetProbeAmounts()
{
    totalProbes = 0;
    totalSuccessfulProbes = 0;
}

void ToolEnvironment::openLogStream(string filename, bool message)
{
    this->logStream.open(filename.c_str());
    this->isExternalLogOpened = true;
    
    // File must be accessible to all
    string path = "./" + filename;
    chmod(path.c_str(), 0766);
    
    if(message)
        (*consoleOut) << "Log of current phase is being written in " << filename << ".\n" << endl;
}

void ToolEnvironment::closeLogStream()
{
    this->logStream.close();
    this->logStream.clear();
    this->isExternalLogOpened = false;
}

bool ToolEnvironment::triggerStop()
{
    /*
     * In case of loss of connectivity, it is possible several threads calls this method. To avoid 
     * multiple contexts launching the emergency stop, there is the following condition (in 
     * addition to a Mutex object).
     */
    
    if(flagEmergencyStop)
    {
        return false;
    }

    flagEmergencyStop = true;
    
    consoleMessagesMutex.lock();
    (*consoleOut) << "\nWARNING: emergency stop has been triggered because of connectivity ";
    (*consoleOut) << "issues.\nRTrack will wait for all remaining threads to complete ";
    (*consoleOut) << "before exiting without carrying out remaining probing tasks.\n" << endl;
    consoleMessagesMutex.unlock();
    
    return true;
}

void ToolEnvironment::recordRouteStepsInDictionnary()
{
    for(list<Trace*>::iterator it = traces.begin(); it != traces.end(); ++it)
    {
        Trace *cur = (*it);
        if(!cur->hasValidRoute())
            continue;
        
        unsigned short routeSize = cur->getRouteSize();
        RouteInterface *route = cur->getRoute();
        for(unsigned short i = 0; i < routeSize; ++i)
        {
            unsigned char TTL = (unsigned char) i + 1;
            InetAddress curIP = route[i].ip;
            if(curIP == InetAddress(0))
                continue;
            
            IPTableEntry *entry = IPTable->lookUp(curIP);
            if(entry == NULL)
            {
                entry = IPTable->create(curIP);
                entry->setTTL(TTL);
            }
            else if(!entry->sameTTL(TTL) && !entry->hasHopCount(TTL))
            {
                entry->recordHopCount(TTL);
            }
            entry->setInitialTTLTimeExceeded(route[i].iTTL);
        }
    }
}

list<InetAddress> ToolEnvironment::listProblematicTargets()
{
    list<InetAddress> res;
    
    // Stretched IPs
    list<IPTableEntry*> sIPs = IPTable->getStretchedIPs();
    for(list<IPTableEntry*>::iterator it = sIPs.begin(); it != sIPs.end(); ++it)
    {
        IPTableEntry *curIP = (*it);
        
        for(list<Trace*>::iterator it = traces.begin(); it != traces.end(); ++it)
        {
            Trace *cur = (*it);
            if(!cur->hasValidRoute())
                continue;
            
            unsigned short routeSize = cur->getRouteSize();
            RouteInterface *route = cur->getRoute();
            for(unsigned short i = 0; i < routeSize; ++i)
            {
                if(route[i].ip == (InetAddress) (*curIP))
                {
                    res.push_back(cur->getTargetIP());
                    break;
                }
            }
        }
    }
    
    // IPs involved in cycles
    list<IPTableEntry*> cIPs = IPTable->getInCyclesIPs();
    for(list<IPTableEntry*>::iterator it = cIPs.begin(); it != cIPs.end(); ++it)
    {
        IPTableEntry *curIP = (*it);
        
        for(list<Trace*>::iterator it = traces.begin(); it != traces.end(); ++it)
        {
            Trace *cur = (*it);
            if(!cur->hasValidRoute())
                continue;
            
            unsigned short routeSize = cur->getRouteSize();
            RouteInterface *route = cur->getRoute();
            for(unsigned short i = 0; i < routeSize; ++i)
            {
                if(route[i].ip == (InetAddress) (*curIP))
                {
                    res.push_back(cur->getTargetIP());
                    break;
                }
            }
        }
    }
    
    // Sorts and remove duplicata before returning final result
    res.sort(InetAddress::smaller);
    InetAddress previous(0);
    for(list<InetAddress>::iterator i = res.begin(); i != res.end(); ++i)
    {
        InetAddress current = (*i);
        if(current == previous)
            res.erase(i--);
        previous = current;
    }
    
    return res;
}

void ToolEnvironment::listRateLimitedCandidates()
{
    for(list<RouteRepair*>::iterator it = routeRepairs.begin(); it != routeRepairs.end(); it++)
    {
        RouteRepair *cur = (*it);
        InetAddress curIP = cur->replacement;
        
        IPTableEntry *curEntry = IPTable->lookUp(curIP);
        if(curEntry != NULL)
        {
            curEntry->setAsRateLimited();
            curEntry->setTargetForRLAnalysis(cur->repairedTraceExample->getTargetIP());
            curEntry->setTTLForRLAnalysis(cur->TTL);
        }
    }
}
