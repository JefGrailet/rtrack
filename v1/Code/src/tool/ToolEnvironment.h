/*
 * ToolEnvironment.h
 *
 *  Created on: May 2, 2017
 *      Author: jefgrailet
 *
 * ToolEnvironment is a class which sole purpose is to provide access to structures or 
 * constants (for the current execution, e.g. timeout delay chosen by the user upon starting 
 * the program) which are relevant to the different parts of the program, such that each component 
 * does not have to be passed individually each time a new object is instantiated.
 *
 * It is essentially an simplified version of TreeNETEnvironment in TreeNET "Arborist".
 */

#ifndef TOOLENVIRONMENT_H_
#define TOOLENVIRONMENT_H_

#include <ostream>
using std::ostream;
#include <fstream>
using std::ofstream;

#include "../common/thread/Mutex.h"
#include "../common/date/TimeVal.h"
#include "../common/inet/InetAddress.h"
#include "../common/inet/NetworkAddress.h"
#include "../prober/DirectProber.h"
#include "utils/StopException.h" // Not used directly here, but provided to all classes that need it this way
#include "structure/IPLookUpTable.h"
#include "structure/Trace.h"
#include "structure/RouteRepair.h"

class ToolEnvironment
{
public:

    // Constants to represent probing protocols
    const static unsigned short PROBING_PROTOCOL_ICMP = 1;
    const static unsigned short PROBING_PROTOCOL_UDP = 2;
    const static unsigned short PROBING_PROTOCOL_TCP = 3;

    // Constants to denote the different modes of verbosity (from any version of TreeNET v3.0)
    const static unsigned short DISPLAY_MODE_LACONIC = 0; // Default
    const static unsigned short DISPLAY_MODE_SLIGHTLY_VERBOSE = 1;
    const static unsigned short DISPLAY_MODE_VERBOSE = 2;
    const static unsigned short DISPLAY_MODE_DEBUG = 3;

    /*
     * Mutex objects used for
     * -accessing the list of traces, 
     * -printing out additionnal messages (slightly verbose to debug), 
     * -triggering emergency stop.
     */
    
    static Mutex tracesListMutex;
    static Mutex consoleMessagesMutex;
    static Mutex emergencyStopMutex;

    // Constructor/destructor
    ToolEnvironment(ostream *consoleOut, 
                    bool externalLogs, 
                    unsigned short probingProtocol, 
                    InetAddress &localIPAddress, 
                    NetworkAddress &LAN, 
                    string &probeAttentionMessage, 
                    TimeVal &timeoutPeriod, 
                    TimeVal &probeRegulatingPeriod, 
                    TimeVal &probeThreadDelay, 
                    unsigned short maxConsecutiveAnonHops, 
                    unsigned short maxConsecutiveRepetitions, 
                    unsigned short RLNbExperiments, 
                    TimeVal &RLDelayExperiments, 
                    double RLMinResponseRatio, 
                    unsigned short displayMode, 
                    unsigned short maxThreads);
    ~ToolEnvironment();

    // Accessers
    inline IPLookUpTable *getIPTable() { return this->IPTable; }
    inline list<Trace*> *getTraces() { return &this->traces; }
    inline list<RouteRepair*> *getRouteRepairs() { return &this->routeRepairs; }
    
    // Accesser to the output stream is not inline, because it depends of the settings
    ostream *getOutputStream();
    inline bool usingExternalLogs() { return this->externalLogs; }
    
    // Method for handling traces without directly accessing the list
    void addTrace(Trace *newTrace);
    inline void sortTraces() { traces.sort(Trace::compare); }
    inline unsigned int getNbTraces() { return traces.size(); }
    bool hasPostProcessedTraces();
    inline bool hasRouteRepairs() { return routeRepairs.size() > 0; }
    void outputTracesMeasured(string filename);
    void outputTracesPostProcessed(string filename);
    void outputRouteRepairs(string filename);
    
    // Probing configuration
    inline unsigned short getProbingProtocol() { return this->probingProtocol; }
    inline InetAddress &getLocalIPAddress() { return this->localIPAddress; }
    inline NetworkAddress &getLAN() { return this->LAN; }
    inline string &getAttentionMessage() { return this->probeAttentionMessage; }
    inline TimeVal &getTimeoutPeriod() { return this->timeoutPeriod; }
    inline TimeVal &getProbeRegulatingPeriod() { return this->probeRegulatingPeriod; }
    inline TimeVal &getProbeThreadDelay() { return this->probeThreadDelay; }
    inline unsigned short getMaxConsecutiveAnonHops() { return this->maxConsecutiveAnonHops; }
    inline unsigned short getMaxCycles() { return this->maxCycles; }
    
    // Bis traces counter
    inline void incBisTracesCounter() { this->bisTracesCounter++; }
    
    // Rate-limit analysis
    inline unsigned short getRLNbExperiments() { return this->RLNbExperiments; }
    inline TimeVal &getRLDelayExperiments() { return this->RLDelayExperiments; }
    inline double getRLMinResponseRatio() { return this->RLMinResponseRatio; }
    
    // Display, threading
    inline unsigned short getDisplayMode() { return this->displayMode; }
    inline bool debugMode() { return (this->displayMode == DISPLAY_MODE_DEBUG); }
    inline unsigned short getMaxThreads() { return this->maxThreads; }
    
    inline void setTimeoutPeriod(TimeVal timeout) { this->timeoutPeriod = timeout; }
    
    // Methods to handle total amounts of (successful) probes
    void updateProbeAmounts(DirectProber *proberObject);
    void resetProbeAmounts();
    inline unsigned int getTotalProbes() { return this->totalProbes; }
    inline unsigned int getTotalSuccessfulProbes() { return this->totalSuccessfulProbes; }
    
    // Method to handle the output stream writing in an output file.
    void openLogStream(string filename, bool message = true);
    void closeLogStream();
    
    /*
     * Method to trigger the (emergency) stop. It is a special method of TreeNETEnvironment which 
     * is meant to force the program to quit when it cannot fully benefit from the host's 
     * resources to conduct measurements/probing. It has a return result (though not used yet), a 
     * boolean one, which is true if the current context successfully triggered the stop 
     * procedure. It will return false it was already triggered by another thread.
     */
    
    bool triggerStop();
    
    // Method to check if the flag for emergency stop is raised.
    inline bool isStopping() { return this->flagEmergencyStop; }
    
    // Method to fill the IP dictionnary with IPs found in the traces
    void recordRouteStepsInDictionnary();
    
    // Method to list target IPs of traces which contain stretched IPs or IPs involved in cycles
    list<InetAddress> listProblematicTargets();
    
    // Method to mark IPs replaced during route repair as potentially rate-limited
    void listRateLimitedCandidates();

private:

    // Structures
    IPLookUpTable *IPTable;
    list<Trace*> traces;
    list<RouteRepair*> routeRepairs;
    
    /*
     * Output streams (main console output and file stream for the external logs). Having both is 
     * useful because the console output stream will still be used to advertise the creation of a 
     * new log file and emergency stop if the user requested probing details to be written in 
     * external logs.
     */
    
    ostream *consoleOut;
    ofstream logStream;
    bool externalLogs, isExternalLogOpened;
    
    // Probing parameters
    unsigned short probingProtocol;
    InetAddress &localIPAddress;
    NetworkAddress &LAN;
    string &probeAttentionMessage;
    TimeVal &timeoutPeriod, &probeRegulatingPeriod, &probeThreadDelay;
    unsigned short maxConsecutiveAnonHops, maxCycles;
    
    // Single field to number the bis traces
    unsigned short bisTracesCounter;
    
    // Fields related to rate-limit analysis (all prefixed with "RL" to avoid confusion)
    unsigned short RLNbExperiments;
    TimeVal &RLDelayExperiments;
    double RLMinResponseRatio;

    /*
     * Value for maintaining display mode; setting it to DISPLAY_MODE_DEBUG (=3) is equivalent to 
     * using the debug mode of ExploreNET. Display modes is a new feature brought by v3.0.
     */
    
    unsigned short displayMode;
    
    // Maximum amount of threads involved during the probing steps
    unsigned short maxThreads;
    
    // Fields to record the amount of (successful) probes used during some stage (can be reset)
    unsigned int totalProbes;
    unsigned int totalSuccessfulProbes;

    // Flag for emergency exit
    bool flagEmergencyStop;

};

#endif /* TOOLENVIRONMENT_H_ */
