/*
 * IPTableEntry.h
 *
 *  Created on: May 3, 2017
 *      Author: jefgrailet
 *
 * This file defines a class "IPTableEntry" which extends the InetAddress class. An entry from 
 * the IP Look-up Table (IPLookUpTable) is essentially an InetAddress with additionnal fields 
 * maintaining data related to the probing work.
 */

#ifndef IPTABLEENTRY_H_
#define IPTABLEENTRY_H_

#include "../../common/date/TimeVal.h"
#include "../../common/inet/InetAddress.h"
#include "RoundRecord.h"

class IPTableEntry : public InetAddress
{
public:

    // Constants to represent uninitialized values
    const static unsigned char NO_KNOWN_TTL = (unsigned char) 255;
    const static unsigned long DEFAULT_TIMEOUT_SECONDS = 2;
    
    // Constructor, destructor
    IPTableEntry(InetAddress ip);
    ~IPTableEntry();
    
    // Accessers/setters
    inline unsigned char getTTL() { return this->TTL; }
    inline TimeVal getPreferredTimeout() { return this->preferredTimeout; }
    inline void setTTL(unsigned char TTL) { this->TTL = TTL; }
    inline void setPreferredTimeout(TimeVal timeout) { this->preferredTimeout = timeout; }
    
    // TTL stuff (re-used from TreeNET's own IPTableEntry class)
    inline bool sameTTL(unsigned char TTL) { return (this->TTL != 0 && this->TTL == TTL); }
    bool hasHopCount(unsigned char hopCount);
    void recordHopCount(unsigned char hopCount);
    
    // Handling additionnal fields
    inline bool isRateLimited() { return this->rateLimited; }
    inline bool isStretched() { return (this->stretchedTTLs.size() > 0); }
    inline bool isCycling() { return (this->inCyclesTTLs.size() > 0); }
    
    inline void setAsRateLimited() { this->rateLimited = true; }
    inline void addStretchedTTL(unsigned char TTL) { this->stretchedTTLs.push_back(TTL); }
    inline void addInCycleTTL(unsigned char TTL) { this->inCyclesTTLs.push_back(TTL); }
    
    // Stored here for convenience, not present in the dictionnary dump
    inline InetAddress getTargetForRLAnalysis() { return this->targetForRLAnalysis; }
    inline unsigned char getTTLForRLAnalysis() { return this->TTLForRLAnalysis; }
    
    inline void setTargetForRLAnalysis(InetAddress target) { targetForRLAnalysis = target; }
    inline void setTTLForRLAnalysis(unsigned char TTL) { TTLForRLAnalysis = TTL; }
    
    // Fingerprinting stuff
    inline unsigned char getInitialTTLTimeExceeded() { return this->initialTTLTimeExceeded; }
    inline unsigned char getInitialTTLEcho() { return this->initialTTLEcho; }
    
    void setInitialTTLTimeExceeded(unsigned char TTL);
    inline void setInitialTTLEcho(unsigned char TTL) { initialTTLEcho = TTL; }
    
    // Rate-limit rounds
    inline list<RoundRecord> *getRoundRecords() { return &this->roundRecords; }
    inline bool hasRoundRecords() { return this->roundRecords.size() > 0; }
    inline void pushRoundRecord(RoundRecord record) { this->roundRecords.push_back(record); }
    
    // Comparison method for sorting purposes
    static bool compare(IPTableEntry *ip1, IPTableEntry *ip2);
	
	// Outputs the entry in human-readable format (! to call after fingerprinting)
    string toString();
    string toStringFingerprint();

private:
    
    unsigned char TTL; // Minimum TTL
    TimeVal preferredTimeout; // Set at pre-scanning
    list<unsigned char> hopCounts; // List of the TTLs at which this IP has been observed (no duplicates)
    
    /*
    * Additionnal fields to keep track of routing problems affecting this IP:
    * -rate-limiting (or rather, the hypothesis that this IP is rate-limited), 
    * -route stretching, 
    * -route cycling.
    */
	
	bool rateLimited, stretched, cycling;
    list<unsigned char> stretchedTTLs; // List of the TTLs when this IP was stretched (with duplicates)
    list<unsigned char> inCyclesTTLs; // List of the TTLs when this IP was in cycles (with duplicates)
    list<RoundRecord> roundRecords; // Only filled if this IP is candidate for rate-limit analysis
    
    InetAddress targetForRLAnalysis;
    unsigned char TTLForRLAnalysis;
    
    /*
     * Last fields are for fingerprinting (in the sense of Yves Vanaubel, see the IMC paper 
     * "Network Fingerprinting: TTL-Based Router Signatures"). Unlike TreeNET, fingerprints here 
     * are limited to <initial TTL from ECHO replies, initial TTL from TTL exceeded messages>.
     */
    
    unsigned char initialTTLTimeExceeded;
    unsigned char initialTTLEcho;
    bool inconsistentITTL; // Set to true if iTTL for a same IP in different traces varies
    
    // Comparison method to sort stretchedTTLs/inCyclesTTLs
    static bool compareTTLs(unsigned char &TTL1, unsigned char &TTL2);

};

#endif /* IPTABLEENTRY_H_ */
