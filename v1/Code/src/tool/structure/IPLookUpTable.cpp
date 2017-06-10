/*
 * IPLookUpTable.cpp
 *
 *  Created on: Sep 29, 2015
 *      Author: jefgrailet
 *
 * Implements the class defined in IPLookUpTable.h (see this file to learn further about the goals 
 * of such class).
 */
 
#include <fstream>
#include <sys/stat.h> // For CHMOD edition
#include <iomanip>

using namespace std;

#include "IPLookUpTable.h"

IPLookUpTable::IPLookUpTable()
{
    this->haystack = new list<IPTableEntry*>[SIZE_TABLE];
}

IPLookUpTable::~IPLookUpTable()
{
    for(unsigned long i = 0; i < SIZE_TABLE; i++)
    {
        list<IPTableEntry*> IPList = this->haystack[i];
        for(list<IPTableEntry*>::iterator j = IPList.begin(); j != IPList.end(); ++j)
        {
            delete (*j);
        }
        haystack[i].clear();
    }
    delete[] haystack;
}

bool IPLookUpTable::isEmpty()
{
    for(unsigned long i = 0; i < SIZE_TABLE; i++)
    {
        list<IPTableEntry*> IPList = this->haystack[i];
        if(IPList.size() > 0)
            return true;
    }
    return false;
}

unsigned int IPLookUpTable::getTotalIPs()
{
    unsigned int total = 0;
    for(unsigned long i = 0; i < SIZE_TABLE; i++)
    {
        list<IPTableEntry*> IPList = this->haystack[i];
        total += IPList.size();
    }
    return total;
}

IPTableEntry *IPLookUpTable::create(InetAddress needle)
{
    unsigned long index = (needle.getULongAddress() >> 12);
    list<IPTableEntry*> *IPList = &(this->haystack[index]);
    
    for(list<IPTableEntry*>::iterator i = IPList->begin(); i != IPList->end(); ++i)
    {
        if((*i)->getULongAddress() == needle.getULongAddress())
        {
            return NULL;
        }
    }
    
    IPTableEntry *newEntry = new IPTableEntry(needle);
    IPList->push_back(newEntry);
    IPList->sort(IPTableEntry::compare);
    return newEntry;
}

IPTableEntry *IPLookUpTable::lookUp(InetAddress needle)
{
    unsigned long index = (needle.getULongAddress() >> 12);
    list<IPTableEntry*> *IPList = &(this->haystack[index]);
    
    for(list<IPTableEntry*>::iterator i = IPList->begin(); i != IPList->end(); ++i)
    {
        if((*i)->getULongAddress() == needle.getULongAddress())
        {
            return (*i);
        }
    }
    
    return NULL;
}

list<InetAddress> IPLookUpTable::listIPs()
{
    list<InetAddress> result;

    for(unsigned long i = 0; i < SIZE_TABLE; i++)
    {
        list<IPTableEntry*> IPList = this->haystack[i];
        for(list<IPTableEntry*>::iterator j = IPList.begin(); j != IPList.end(); ++j)
            result.push_back(InetAddress((InetAddress) (*(*j))));
    }
    
    return result;
}

void IPLookUpTable::outputDictionnary(string filename)
{
    string output = "";
    
    for(unsigned long i = 0; i < SIZE_TABLE; i++)
    {
        list<IPTableEntry*> IPList = this->haystack[i];
        for(list<IPTableEntry*>::iterator j = IPList.begin(); j != IPList.end(); ++j)
        {
            IPTableEntry *cur = (*j);
            string curStr = cur->toString();
            
            if(!curStr.empty())
                output += curStr;
        }
    }
    
    ofstream newFile;
    newFile.open(filename.c_str());
    newFile << output;
    newFile.close();
    
    // File must be accessible to all
    string path = "./" + filename;
    chmod(path.c_str(), 0766);
}

void IPLookUpTable::outputRoundRecords(string filename)
{
    stringstream ss;
    
    for(unsigned long i = 0; i < SIZE_TABLE; i++)
    {
        list<IPTableEntry*> IPList = this->haystack[i];
        for(list<IPTableEntry*>::iterator j = IPList.begin(); j != IPList.end(); ++j)
        {
            IPTableEntry *cur = (*j);
            if(cur->hasRoundRecords())
            {
                ss << (InetAddress) (*cur) << "\n";
                list<RoundRecord> *records = cur->getRoundRecords();
                for(list<RoundRecord>::iterator it = records->begin(); it != records->end(); it++)
                    ss << (*it).toString() << "\n";
            }
        }
    }
    
    ofstream newFile;
    newFile.open(filename.c_str());
    newFile << ss.str();
    newFile.close();
    
    // File must be accessible to all
    string path = "./" + filename;
    chmod(path.c_str(), 0766);
}

list<IPTableEntry*> IPLookUpTable::getStretchedIPs()
{
    list<IPTableEntry*> result;
    
    for(unsigned long i = 0; i < SIZE_TABLE; i++)
    {
        list<IPTableEntry*> IPList = this->haystack[i];
        for(list<IPTableEntry*>::iterator j = IPList.begin(); j != IPList.end(); ++j)
        {
            IPTableEntry *cur = (*j);
            if(cur->isStretched())
                result.push_back(cur);
        }
    }
    
    return result;
}

list<IPTableEntry*> IPLookUpTable::getInCyclesIPs()
{
    list<IPTableEntry*> result;
    
    for(unsigned long i = 0; i < SIZE_TABLE; i++)
    {
        list<IPTableEntry*> IPList = this->haystack[i];
        for(list<IPTableEntry*>::iterator j = IPList.begin(); j != IPList.end(); ++j)
        {
            IPTableEntry *cur = (*j);
            if(cur->isCycling())
                result.push_back(cur);
        }
    }
    
    return result;
}

list<IPTableEntry*> IPLookUpTable::getRateLimitedIPs()
{
    list<IPTableEntry*> result;
    
    for(unsigned long i = 0; i < SIZE_TABLE; i++)
    {
        list<IPTableEntry*> IPList = this->haystack[i];
        for(list<IPTableEntry*>::iterator j = IPList.begin(); j != IPList.end(); ++j)
        {
            IPTableEntry *cur = (*j);
            if(!cur->isRateLimited())
                continue;
            
            if(cur->getTargetForRLAnalysis() != InetAddress(0) && cur->getTTLForRLAnalysis() > 0)
                result.push_back(cur);
        }
    }
    
    return result;
}
