#include <cstdlib>
#include <set>
using std::set;
#include <ctime>
#include <iostream>
using std::cout;
using std::cin;
using std::endl;
using std::exit;
using std::flush;
#include <fstream>
using std::ofstream;
using std::ios;
#include <memory>
using std::auto_ptr;
#include <string>
using std::string;
#include <list>
using std::list;
#include <algorithm> // For transform() function
#include <getopt.h> // For options parsing
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <ctime> // To obtain current time (for output file)
#include <unistd.h> // For usleep() function

#include "common/inet/InetAddress.h"
#include "common/inet/InetAddressException.h"
#include "common/inet/NetworkAddress.h"
#include "common/inet/NetworkAddressSet.h"
#include "common/inet/InetAddressSet.h"
#include "common/thread/Thread.h"
#include "common/thread/Runnable.h"
#include "common/thread/Mutex.h"
#include "common/thread/ConditionVariable.h"
#include "common/thread/MutexException.h"
#include "common/thread/TimedOutException.h"
#include "common/date/TimeVal.h"
#include "common/utils/StringUtils.h"
#include "common/random/PRNGenerator.h"
#include "common/random/Uniform.h"

#include "prober/icmp/DirectICMPProber.h"
#include "prober/DirectProber.h"

#include "tool/ToolEnvironment.h"
#include "tool/utils/TargetParser.h"
#include "tool/prescanning/NetworkPrescanner.h"
#include "tool/traceroute/ParisTracerouteTask.h"
#include "tool/repair/RouteRepairer.h"
#include "tool/postprocessing/RoutePostProcessor.h"
#include "tool/fingerprinting/FingerprintMaker.h"
#include "tool/rate-limit-analysis/RoundScheduler.h"

// Simple function to display usage.

void printInfo()
{
    cout << "Summary\n";
    cout << "=======\n";
    cout << "\n";
    cout << "RTrack is a topology discovery tool which aims at collecting traces towards a\n";
    cout << "set of targets and detect the various anomalies that can affect the collected\n";
    cout << "data. Among others, it tries to detect rate-limited interfaces and evaluates\n";
    cout << "their rate limit and considers all IP interfaces which appear in multiple\n";
    cout << "routes at different distances (in TTL) due to routing policies and/or traffic\n";
    cout << "engineering. This encompasses route stretching (i.e., an IP appears only once\n";
    cout << "per route, but at different TTLs) and route cycling (i.e., a same IP appears\n";
    cout << "multiple times in a same route).\n";
    cout << "\n";
    cout << "The name \"RTrack\" can denote several things, as the R can substitute for\n";
    cout << "\"Rate-limit\", \"Route stretching\" or \"Route cycling\", while the \"Track\"\n";
    cout << "simply recalls its purpose.\n";
    cout.flush();
}

void printUsage()
{
    cout << "Usage\n";
    cout << "=====\n";
    cout << "\n";
    cout << "You can use RTrack as follows:\n";
    cout << "\n";
    cout << "./rtrack [target n°1],[target n°2],[...]\n";
    cout << "\n";
    cout << "where each target can be:\n";
    cout << "-a single IP,\n";
    cout << "-a whole IP block (in CIDR notation),\n";
    cout << "-a file containing a list of the notations mentioned above, which each item\n";
    cout << " being separated with \\n.\n";
    cout << "\n";
    cout << "You can use various options and flags to handle the settings of TreeNET, such\n";
    cout << "as probing protocol, the amount of threads used in multi-threaded parts of the\n";
    cout << "application, etc. These options and flags are detailed below.\n";
    cout << "\n";
    cout << "Short   Verbose                             Expected value\n";
    cout << "-----   -------                             --------------\n";
    cout << "\n";
    cout << "-e      --probing-egress-interface          IP or DNS\n";
    cout << "\n";
    cout << "Interface name through which probing/response packets exit/enter (default is\n";
    cout << "the first non-loopback IPv4 interface in the active interface list). Use this\n";
    cout << "option if your machine has multiple network interface cards and if you want to\n";
    cout << "prefer one interface over the others.\n";
    cout << "\n";
    cout << "-m      --probing-payload-message           String\n";
    cout << "\n";
    cout << "Use this option to edit the message carried in the payload of the probes. This\n";
    cout << "message should just advertise that the probes are not sent for malicious\n";
    cout << "purposes, only for measurements. By default, it states \"NOT AN ATTACK\".\n";
    cout << "\n";
    cout << "-p      --probing-protocol                 \"UDP\", \"TCP\" or \"ICMP\"\n";
    cout << "\n";
    cout << "Use this option to specify the base protocol used to probe target addresses.\n";
    cout << "By default, it is ICMP.\n";
    cout << "\n";
    cout << "-r      --probing-regulating-period         Integer (amount of milliseconds)\n";
    cout << "\n";
    cout << "Use this option to edit the minimum amount of milliseconds between two\n";
    cout << "consecutive probes sent by a same thread. By default, this value is set to 50.\n";
    cout << "\n";
    cout << "-t      --probing-timeout-period            Integer (amount of milliseconds)\n";
    cout << "\n";
    cout << "Use this option to edit the amount of milliseconds spent waiting before\n";
    cout << "diagnosing a timeout. Editing this value will especially impact the network\n";
    cout << "pre-scanning phase (i.e., phase where the liveness of target IPs is checked).\n";
    cout << "By default, this value is set to 2500 (2,5 seconds).\n";
    cout << "\n";
    cout << "-n      --max-consecutive-anonymous-hops    Integer (in [1,255])\n";
    cout << "\n";
    cout << "Use this option to edit the maximum amount of consecutive anonymous hops seen\n";
    cout << "while tracing before interrupting it. By default, it is 3. Increasing this\n";
    cout << "maximum can result in sending more probes towards unreachable targets.\n";
    cout << "\n";
    cout << "-n      --max-cycles                        Integer (in [1,255])\n";
    cout << "\n";
    cout << "Use this option to edit the maximum amount of consecutive cycles seen while\n";
    cout << "tracing before interrupting it. By default, it is 4. Increasing this maximum\n";
    cout << "can result in sending more probes towards unreachable targets for which the\n";
    cout << "packets are stuck in a routing loop.\n";
    cout << "\n";
    cout << "-s      --use-pre-scanning                  None (flag)\n";
    cout << "\n";
    cout << "Add this flag to your command line to schedule a pre-scanning phase before\n";
    cout << "probing for traceroute records. Pre-scanning consists in eliminating all\n";
    cout << "unresponsive IPs among the targets to only collect traces towards responsive\n";
    cout << "IPs. It has the advantage of reducing the probing work and ensuring a maximum\n";
    cout << "of complete traces (i.e., traces that reach a destination).\n";
    cout << "\n";
    cout << "-a      --concurrency-amount-threads        Integer (amount of threads)\n";
    cout << "\n";
    cout << "Use this option to edit the amount of concurrent threads performing traceroute\n";
    cout << "measurements at the same time. By default, this value is set to 256.\n";
    cout << "\n";
    cout << "-d      --concurrency-delay-threading       Integer (amount of milliseconds)\n";
    cout << "\n";
    cout << "Use this option to edit the minimum amount of milliseconds spent waiting\n";
    cout << "between two immediately consecutive threads. This value is set to 250 (i.e.,\n";
    cout << "0,25s) by default. This delay is meant to avoid sending too many probes at the\n";
    cout << "same time upon scheduling new probing threads. Indeed, a small delay for a\n";
    cout << "large amount of threads could potentially cause congestion and make the whole\n";
    cout << "application ineffective.\n";
    cout << "\n";
    cout << "-b      --amount-bis-traces                 Integer (in [0, 255])\n";
    cout << "\n";
    cout << "Use this option to edit the amount of \"bis\" traces RTrack will collect for\n";
    cout << "traces which contain stretched IPs or cycles, after the initial traceroute and\n";
    cout << "route analysis. Having a\nsecond/third/... opinion for the route towards the\n";
    cout << "associated target IPs is meant to check if the observed anomalies are a result\n";
    cout << "of random load-balancing or anomalies that persist in time. Note that these\n";
    cout << "additionnal traces are neither analyzed, nor post-processed. You can also set\n";
    cout << "the amount of bis traces to 0 in order to prevent the collection of bis traces\n";
    cout << "at all.\n";
    cout << "\n";
    cout << "-x      --rate-limit-amount-experiments     Integer (in [0, max. #threads])\n";
    cout << "\n";
    cout << "Use this option to set the amount of experiments conducted during a round for\n";
    cout << "evaluating the rate-limit of an IP interface. By default, it is set to 15. You\n";
    cout << "can set it to 0 to prevent RTrack from estimating rate-limit if you do not\n";
    cout << "need it and prefer to save time and network resources.\n";
    cout << "\n"; 
    cout << "-y      --rate-limit-delay-experiments      Integer (amount of milliseconds)\n";
    cout << "\n";
    cout << "Use this option to set the \"cooldown\" delay between two consecutive\n";
    cout << "experiments of a round while evaluating the rate-limit of an IP interface. By\n";
    cout << "default, it is set to 2 seconds.\n";
    cout << "\n";
    cout << "-z      --rate-limit-min-response-rate      Double (in ]0,100[)\n";
    cout << "\n";
    cout << "Use this option to set the threshold minimum response ratio from an IP probed\n";
    cout << "during rate-limit evaluation of an IP interface. When the mean response ratio\n";
    cout << "of a probing round gets below that threshold, no subsequent round will be\n";
    cout << "scheduled for that IP. By default, the threshold is set to 5%.\n";
    cout << "\n";
    cout << "-l      --label-output                      String\n";
    cout << "\n";
    cout << "Use this option to edit the label that will be used to name the output files\n";
    cout << "produced by RTrack (.traces for the measured traces, .ip for the annotated\n";
    cout << "IP dictionnary, .post-processed for post-processed traces). By default,\n";
    cout << "RTrack uses the time at which it was started, in the format\n";
    cout << "dd-mm-yyyy hh:mm:ss.\n";
    cout << "\n";
    cout << "-v      --verbosity                         0, 1 or 2\n";
    cout << "\n";
    cout << "Use this option to handle the verbosity of the console output produced by\n";
    cout << "TreeNET. Each accepted value corresponds to a \"mode\":\n";
    cout << "\n";
    cout << "* 0: it is the default verbosity. In this mode, it only displays the targets\n";
    cout << "  for which the route has been computed, but not the route it obtained (of\n";
    cout << "  course, it is still written in the final output file).\n";
    cout << "\n";
    cout << "* 1: this is the \"slightly verbose\" mode. RTrack displays in console the\n";
    cout << "  routes it obtained for each target when available.\n";
    cout << "\n";
    cout << "* 2: this mode stacks up on the previous and prints out a series of small\n";
    cout << "  logs for each probe once it has been carried out. It is equivalent to a\n";
    cout << "  debug mode.\n";
    cout << "\n";
    cout << "  WARNING: this debug mode is extremely verbose and should only be considered\n";
    cout << "  for unusual situations where investigating the result of each probe becomes\n";
    cout << "  necessary. Do not use it for large-scale work, as redirecting the console\n";
    cout << "  output to files might produce unnecessarily large files.\n";
    cout << "\n";
    cout << "-k      --external-logs                     None (flag)\n";
    cout << "\n";
    cout << "Add this flag to your command line to place the probing logs in separate\n";
    cout << "output files rather than having them in the main console output. The goal of\n";
    cout << "this feature is to allow the user to have a short summary of the execution of\n";
    cout << "RTrack at the end (to learn quickly elapsed time for each phase, amount of\n";
    cout << "probes, etc.) while the probing details remain accessible in separate files.\n";
    cout << "Given [label], the label used for output files (either edited with -l or set\n";
    cout << "by default to dd-mm-yyyy hh:mm:ss), the logs will be named Log_[label]_[phase]\n";
    cout << "where [phase] is either: pre-scanning, traceroute, route_analysis,\n";
    cout << "fingerprinting or rate-limit_analysis.\n";
    cout << "\n";
    cout << "-c      --credits                           None (flag)\n";
    cout << "\n";
    cout << "Add this flag to your command line to display the version of RTrack and some\n";
    cout << "credits. It will not run further in this case, though -h and -i flags can be\n";
    cout << "used in addition.\n";
    cout << "\n";
    cout << "-h      --help                              None (flag)\n";
    cout << "\n";
    cout << "Add this flag to your command line to know how to use RTrack and see the\n";
    cout << "complete list of options and flags and how they work. It will not run further\n";
    cout << "after displaying this, though -c and -i flags can be used in addition.\n";
    cout << "\n";
    cout << "-i      --info                              None (flag)\n";
    cout << "\n";
    cout << "Add this flag to your command line to read a summary of the purpose of RTrack.\n";
    cout << "It will not run further after displaying this, though -c and -h flags can be\n";
    cout << "used in addition.\n";
    cout << "\n";
    
    cout.flush();
}

void printVersion()
{
    cout << "Version and credits\n";
    cout << "===================\n";
    cout << "\n";
    cout << "RTrack v1.0, written by Jean-François Grailet (05/2017).\n";
    cout << "Derived from TreeNET, also written by J.-F. Grailet (2015-2017).\n";
    cout << "TreeNET was originally based on ExploreNET version 2.1, copyright (c) 2013 Mehmet Engin Tozal.\n";
    cout << "\n";
    
    cout.flush();
}

// Simple function to get the current time as a string object.

string getCurrentTimeStr()
{
    time_t rawTime;
    struct tm *timeInfo;
    char buffer[80];

    time(&rawTime);
    timeInfo = localtime(&rawTime);

    strftime(buffer, 80, "%d-%m-%Y %T", timeInfo);
    string timeStr(buffer);
    
    return timeStr;
}

// Simple function to convert an elapsed time (in seconds) into days/hours/mins/secs format

string elapsedTimeStr(unsigned long elapsedSeconds)
{
    if(elapsedSeconds == 0)
    {
        return "less than one second";
    }

    unsigned short secs = (unsigned short) elapsedSeconds % 60;
    unsigned short mins = (unsigned short) (elapsedSeconds / 60) % 60;
    unsigned short hours = (unsigned short) (elapsedSeconds / 3600) % 24;
    unsigned short days = (unsigned short) elapsedSeconds / 86400;
    
    stringstream ss;
    if(days > 0)
    {
        if(days > 1)
            ss << days << " days ";
        else
            ss << "1 day ";
    }
    if(hours > 0)
    {
        if(hours > 1)
            ss << hours << " hours ";
        else
            ss << "1 hour ";
    }
    if(mins > 0)
    {
        if(mins > 1)
            ss << mins << " minutes ";
        else
            ss << "1 minute ";
    }
    if(secs > 1)
        ss << secs << " seconds";
    else
        ss << secs << " second";
    
    return ss.str();    
}


// Main function; deals with inputs and launches thread(s)

int main(int argc, char *argv[])
{
    // Default parameters (can be edited by user)
    InetAddress localIPAddress;
    unsigned char LANSubnetMask = 0;
    unsigned short probingProtocol = ToolEnvironment::PROBING_PROTOCOL_ICMP;
    string probeAttentionMessage = string("NOT an ATTACK (mail: Jean-Francois.Grailet@ulg.ac.be)");
    TimeVal timeoutPeriod(1, TimeVal::HALF_A_SECOND); // 1s + 500 000 microseconds = 1,5s
    TimeVal probeRegulatingPeriod(0, 50000); // 0,05s
    TimeVal probeThreadDelay(0, 250000); // 0,25s
    unsigned short maxConsecutiveAnonHops = 3;
    unsigned short maxCycles = 4;
    bool usePrescanning = false;
    unsigned short bisTraces = 2; // Amount of opinions for stretched/with cycle(s) traces
    unsigned short RLNbExperiments = 15;
    TimeVal RLDelayExperiments(2, 0); // 2s
    double RLMinResponseRatio = 5.0;
    bool kickLogs = false;
    unsigned short displayMode = ToolEnvironment::DISPLAY_MODE_LACONIC;
    unsigned short nbThreads = 256;
    string outputFileName = ""; // Gets a default value later if not set by user.
    
    // Values to check if info, usage, version... should be displayed.
    bool displayInfo = false, displayUsage = false, displayVersion = false;
    
    /*
     * PARSING ARGUMENT
     * 
     * The main argument (target prefixes or input files, each time separated by commas) can be 
     * located anywhere. To make things simple for getopt_long(), argv is processed to find it and 
     * put it at the end. If not found, RTrack stops and displays an error message.
     */
    
    int totalArgs = argc;
    string targetsStr = ""; // List of targets (input files or plain targets)
    bool found = false;
    bool flagParam = false; // True if a value for a parameter is expected
    for(int i = 1; i < argc; i++)
    {
        if(argv[i][0] == '-')
        {
            switch(argv[i][1])
            {
                case 'c':
                case 'h':
                case 'i':
                case 'k':
                case 's':
                    break;
                default:
                    flagParam = true;
                    break;
            }
        }
        else if(flagParam)
        {
            flagParam = false;
        }
        else
        {
            // Argument found!
            char *arg = argv[i];
            for(int j = i; j < argc - 1; j++)
                argv[j] = argv[j + 1];
            argv[argc - 1] = arg;
            found = true;
            totalArgs--;
            break;
        }
    }
    
    targetsStr = argv[argc - 1];   
    
    /*
     * PARSING PARAMETERS
     *
     * In addition to the main argument parsed above, TreeNET provides various input flags which 
     * can be used to handle the probing parameters, concurrency parameters, alias resolution 
     * parameters and a few more features (like setting the message sent with the ICMP probes and 
     * the label of the output files).
     */
     
    int opt = 0;
    int longIndex = 0;
    const char* const shortOpts = "a:b:cd:e:hikl:m:n:o:p:r:st:v:x:y:z:";
    const struct option longOpts[] = {
            {"probing-egress-interface", required_argument, NULL, 'e'}, 
            {"probing-payload-message", required_argument, NULL, 'm'}, 
            {"probing-protocol", required_argument, NULL, 'p'}, 
            {"probing-regulating-period", required_argument, NULL, 'r'}, 
            {"probing-timeout-period", required_argument, NULL, 't'}, 
            {"max-consecutive-anonymous-hops", required_argument, NULL, 'n'}, 
            {"max-cycles", required_argument, NULL, 'o'}, 
            {"use-pre-scanning", no_argument, NULL, 's'}, 
            {"concurrency-amount-threads", required_argument, NULL, 'a'}, 
            {"concurrency-delay-threading", required_argument, NULL, 'd'}, 
            {"amount-bis-traces", required_argument, NULL, 'b'}, 
            {"rate-limit-amount-experiments", required_argument, NULL, 'x'}, 
            {"rate-limit-delay-experiments", required_argument, NULL, 'y'}, 
            {"rate-limit-min-response-rate", required_argument, NULL, 'z'}, 
            {"label-output", required_argument, NULL, 'l'}, 
            {"verbosity", required_argument, NULL, 'v'}, 
            {"external-logs", no_argument, NULL, 'k'}, 
            {"credits", no_argument, NULL, 'c'}, 
            {"help", no_argument, NULL, 'h'}, 
            {"info", no_argument, NULL, 'i'}
    };
    
    string optargSTR;
    unsigned long val;
    unsigned long sec;
    unsigned long microSec;
    double valDouble;
    
    try
    {
        while((opt = getopt_long(totalArgs, argv, shortOpts, longOpts, &longIndex)) != -1)
        {
            /*
             * Beware: use the line optargSTR = string(optarg); ONLY for flags WITH arguments !! 
             * Otherwise, it prevents the code from recognizing flags like -v, -h or -g (because 
             * they require no argument) and make it throw an exception... To avoid this, a second 
             * switch is used.
             *
             * (this error is still present in ExploreNET v2.1)
             */
            
            switch(opt)
            {
                case 'c':
                case 'h':
                case 'i':
                case 'k':
                case 's':
                    break;
                default:
                    optargSTR = string(optarg);
                    
                    /*
                     * For future readers: optarg is of type extern char*, and is defined in getopt.h.
                     * Therefore, you will not find the declaration of this variable in this file.
                     */
                    
                    break;
            }
            
            // Now we can actually treat the options.
            int gotNb = 0;
            switch(opt)
            {
                case 'e':
                    try
                    {
                        localIPAddress = InetAddress::getLocalAddressByInterfaceName(optargSTR);
                    }
                    catch (InetAddressException &e)
                    {
                        cout << "Error for -e option: cannot obtain any IP address ";
                        cout << "assigned to the interface \"" + optargSTR + "\". ";
                        cout << "Please fix the argument for this option before ";
                        cout << "restarting.\n" << endl;
                        return 1;
                    }
                    break;
                case 'm':
                    probeAttentionMessage = optargSTR;
                    break;
                case 'p':
                    std::transform(optargSTR.begin(), optargSTR.end(), optargSTR.begin(),::toupper);
                    if(optargSTR == string("UDP"))
                        probingProtocol = ToolEnvironment::PROBING_PROTOCOL_UDP;
                    else if(optargSTR == string("TCP"))
                        probingProtocol = ToolEnvironment::PROBING_PROTOCOL_TCP;
                    else if(optargSTR != string("ICMP"))
                    {
                        cout << "Warning for option -p: unrecognized protocol " << optargSTR;
                        cout << ". Please select a protocol between the following three: ";
                        cout << "ICMP, UDP and TCP. Note that ICMP is the default ";
                        cout << "protocol.\n" << endl;
                    }
                    break;
                case 'r':
                    val = 1000 * StringUtils::string2Ulong(optargSTR);
                    if(val > 0)
                    {
                        sec = val / TimeVal::MICRO_SECONDS_LIMIT;
                        microSec = val % TimeVal::MICRO_SECONDS_LIMIT;
                        probeRegulatingPeriod.setTime(sec, microSec);
                    }
                    else
                    {
                        cout << "Warning for -r option: a negative value (or 0) was parsed. ";
                        cout << "RTrack will use the default value for the probe regulating ";
                        cout << "period (= 50ms).\n" << endl;
                    }
                    break;
                case 's':
                    usePrescanning = true;
                    break;
                case 't':
                    val = 1000 * StringUtils::string2Ulong(optargSTR);
                    if(val > 0)
                    {
                        sec = val / TimeVal::MICRO_SECONDS_LIMIT;
                        microSec = val % TimeVal::MICRO_SECONDS_LIMIT;
                        timeoutPeriod.setTime(sec, microSec);
                    }
                    else
                    {
                        cout << "Warning for -r option: a negative value (or 0) was parsed. ";
                        cout << "RTrack will use the default value for the timeout period ";
                        cout << "(= 2,5s).\n" << endl;
                    }
                    break;
                case 'n':
                    gotNb = std::atoi(optargSTR.c_str());
                    if(gotNb > 0 && gotNb < 256)
                    {
                        maxConsecutiveAnonHops = (unsigned short) gotNb;
                    }
                    else
                    {
                        cout << "Warning for -n option: a value smaller than 1 or greater ";
                        cout << "than 255 was parsed. RTrack will use the default value ";
                        cout << "for the maximum amount of consecutive anonymous hops ";
                        cout << "before stopping the tracing (= 3).\n" << endl;
                    }
                    break;
                case 'o':
                    gotNb = std::atoi(optargSTR.c_str());
                    if(gotNb > 0 && gotNb < 256)
                    {
                        maxCycles = (unsigned short) gotNb;
                    }
                    else
                    {
                        cout << "Warning for -o option: a value smaller than 1 or greater ";
                        cout << "than 255 was parsed. RTrack will use the default value ";
                        cout << "for the maximum amount of cycles before stopping the ";
                        cout << "tracing (= 4).\n" << endl;
                    }
                    break;
                case 'a':
                    gotNb = std::atoi(optargSTR.c_str());
                    if (gotNb > 0 && gotNb < 32767)
                    {
                        nbThreads = (unsigned short) gotNb;
                    }
                    else
                    {
                        cout << "Warning for -a option: a value smaller than 1 or greater ";
                        cout << "than 32766 was parsed. RTrack will use the default amount ";
                        cout << "of threads (= 256).\n" << endl;
                    }
                    break;
                case 'd':
                    val = 1000 * StringUtils::string2Ulong(optargSTR);
                    if(val > 0)
                    {
                        sec = val / TimeVal::MICRO_SECONDS_LIMIT;
                        microSec = val % TimeVal::MICRO_SECONDS_LIMIT;
                        probeThreadDelay.setTime(sec, microSec);
                    }
                    else
                    {
                        cout << "Warning for -d option: a negative value (or 0) was parsed. ";
                        cout << "RTrack will use the default value for the delay between ";
                        cout << "the launch of two consecutive threads (= 250ms).\n" << endl;
                    }
                    break;
                case 'b':
                    gotNb = std::atoi(optargSTR.c_str());
                    if (gotNb >= 0 && gotNb < 256)
                    {
                        bisTraces = (unsigned short) gotNb;
                    }
                    else
                    {
                        cout << "Warning for -b option: a value smaller than 0 or greater ";
                        cout << "than 255 was parsed. RTrack will use the default amount ";
                        cout << "of bis traces (= 2).\n" << endl;
                    }
                    break;
                case 'x':
                    gotNb = std::atoi(optargSTR.c_str());
                    if(gotNb >= 0 && gotNb < nbThreads)
                    {
                        RLNbExperiments = gotNb;
                    }
                    else
                    {
                        cout << "Warning for -x option: a value smaller than 0 or greater ";
                        cout << "than the maximum amount of threads was parsed. RTrack will ";
                        cout << "use the default value for the amount of experiments per round ";
                        cout << "while evaluating the rate-limit of an IP (= 15).\n" << endl;
                    }
                    break;
                case 'y':
                    val = 1000 * StringUtils::string2Ulong(optargSTR);
                    if(val > 0)
                    {
                        sec = val / TimeVal::MICRO_SECONDS_LIMIT;
                        microSec = val % TimeVal::MICRO_SECONDS_LIMIT;
                        RLDelayExperiments.setTime(sec, microSec);
                    }
                    else
                    {
                        cout << "Warning for -y option: a negative value (or 0) was parsed. ";
                        cout << "RTrack will use the default value for the delay between ";
                        cout << "two rounds during the evaluation of the rate-limit of an IP ";
                        cout << "(= 2s).\n" << endl;
                    }
                    break;
                case 'z':
                    valDouble = StringUtils::string2double(optargSTR);
                    if(valDouble >= 0.0 && valDouble < 100.0)
                    {
                        RLMinResponseRatio = valDouble;
                    }
                    else
                    {
                        cout << "Warning for -z option: a value outside the suggested range ";
                        cout << "(i.e., [0,100[) was provided. TreeNET will use the default ";
                        cout << "value for this option (= 25).\n" << endl;
                    }
                    break;
                case 'l':
                    outputFileName = optargSTR;
                    break;
                case 'v':
                    gotNb = std::atoi(optargSTR.c_str());
                    if(gotNb >= 0 && gotNb <= 2)
                        displayMode = (unsigned short) gotNb;
                        if(displayMode == 2)
                            displayMode++; // To debug mode ("verbose" technically not used)
                    else
                    {
                        cout << "Warning for -v option: an unrecognized mode (i.e., value ";
                        cout << "out of [0,3]) was provided. RTrack will use the ";
                        cout << "laconic mode (default mode).\n" << endl;
                    }
                    break;
                case 'k':
                    kickLogs = true;
                    break;
                case 'c':
                    displayVersion = true;
                    break;
                case 'h':
                    displayUsage = true;
                    break;
                case 'i':
                    displayInfo = true;
                    break;
                default:
                    break;
            }
        }
    }
    catch(std::logic_error &le)
    {
        cout << "Use -h or --help to get more details on how to use TreeNET." << endl;
        return 1;
    }
    
    if(displayInfo || displayUsage || displayVersion)
    {
        if(displayInfo)
            printInfo();
        if(displayUsage)
            printUsage();
        if(displayVersion)
            printVersion();
        return 0;
    }
    
    if(!found)
    {
        cout << "No target prefix or target file was provided. Use -h or --help to get more ";
        cout << "details on how to use RTrack." << endl;
        return 0;
    }
    
    /*
     * SETTING THE ENVIRONMENT
     *
     * Before listing target IPs, the initialization of CRiyte is completed by getting the local 
     * IP and the local subnet mask and creating a ToolEnvironment object, a singleton which 
     * will be passed by pointer to other classes of RTrack to be able to get all the current 
     * settings, which are either default values either values parsed in the parameters provided 
     * by the user. The singleton also provides access to data structures other classes should 
     * be able to access.
     */

    if(localIPAddress.isUnset())
    {
        try
        {
            localIPAddress = InetAddress::getFirstLocalAddress();
        }
        catch(InetAddressException &e)
        {
            cout << "Cannot obtain a valid local IP address for probing. ";
            cout << "Please check your connectivity." << endl;
            return 1;
        }
    }

    if(LANSubnetMask == 0)
    {
        try
        {
            LANSubnetMask = NetworkAddress::getLocalSubnetPrefixLengthByLocalAddress(localIPAddress);
        }
        catch(InetAddressException &e)
        {
            cout << "Cannot obtain subnet mask of the local area network (LAN) .";
            cout << "Please check your connectivity." << endl;
            return 1;
        }
    }

    NetworkAddress LAN(localIPAddress, LANSubnetMask);
    
    /*
     * We determine now the label of the output files. Here, it is either provided by the user 
     * (via -l flag), either it is set to the current date (dd-mm-yyyy hh:mm:ss).
     */
    
    string newFileName = "";
    if(outputFileName.length() > 0)
    {
        newFileName = outputFileName;
    }
    else
    {
        // Get the current time for the name of output file
        time_t rawTime;
        struct tm *timeInfo;
        char buffer[80];

        time(&rawTime);
        timeInfo = localtime(&rawTime);

        strftime(buffer, 80, "%d-%m-%Y %T", timeInfo);
        string timeStr(buffer);
        
        newFileName = timeStr;
    }
    
    /*
     * The code now checks if it can open a socket at all to properly advertise the user should 
     * use "sudo" or "su". Not putting this step would result in RTrack scheduling probing work 
     * and immediately trigger emergency stop (which should only occur when, after doing some 
     * probing work, software resources start lacking), which is not very elegant.
     */
    
    try
    {
        DirectProber *test = new DirectICMPProber(probeAttentionMessage, 
                                                  timeoutPeriod, 
                                                  probeRegulatingPeriod, 
                                                  DirectICMPProber::DEFAULT_LOWER_ICMP_IDENTIFIER, 
                                                  DirectICMPProber::DEFAULT_UPPER_ICMP_IDENTIFIER, 
                                                  DirectICMPProber::DEFAULT_LOWER_ICMP_SEQUENCE, 
                                                  DirectICMPProber::DEFAULT_UPPER_ICMP_SEQUENCE, 
                                                  false);
        
        delete test;
    }
    catch(SocketException &e)
    {
        cout << "Unable to create sockets. Try running RTrack as a privileged user (for example, ";
        cout << "try with sudo)." << endl;
        return 1;
    }
    
    // Initialization of the environment
    ToolEnvironment *env = new ToolEnvironment(&cout, 
                                               kickLogs, 
                                               probingProtocol, 
                                               localIPAddress, 
                                               LAN, 
                                               probeAttentionMessage, 
                                               timeoutPeriod, 
                                               probeRegulatingPeriod, 
                                               probeThreadDelay, 
                                               maxConsecutiveAnonHops, 
                                               maxCycles, 
                                               RLNbExperiments, 
                                               RLDelayExperiments, 
                                               RLMinResponseRatio, 
                                               displayMode, 
                                               nbThreads);

    // Various variables/structures which should be considered when catching some exception
    ostream *out = env->getOutputStream();
    TargetParser *parser = NULL;
    NetworkPrescanner *prescanner = NULL;
    Thread **tracerouteTasks = NULL;
    RouteRepairer *repairer = NULL;
    RoutePostProcessor *postProcessor = NULL;
    FingerprintMaker *fingerprintMaker = NULL;
    RoundScheduler *RLScheduler = NULL;
    unsigned short nbTasks = nbThreads; // By default, might be edited later
    
    try
    {
        // Parses inputs and gets target lists
        parser = new TargetParser(env);
        parser->parseCommandLine(targetsStr);
        
        cout << "RTrack v1.0 (time at start: " << getCurrentTimeStr() << ")\n" << endl;
        
        // Announces that it will ignore LAN.
        if(parser->targetsEncompassLAN())
        {
            cout << "Target IPs encompass the LAN of the vantage point ("
                 << LAN.getSubnetPrefix() << "/" << (unsigned short) LAN.getPrefixLength() 
                 << "). IPs belonging to the LAN will be ignored.\n" << endl;
        }

        list<InetAddress> targets = parser->getInitialTargets();
        
        // Stops if no target at all
        if(targets.size() == 0)
        {
            cout << "No target to probe." << endl;
            delete parser;
            parser = NULL;
            
            cout << "Use \"--help\" or \"-h\" parameter to reach help" << endl;
            delete env;
            return 1;
        }
        
        if(usePrescanning)
        {
            /*
             * NETWORK PRE-SCANNING
             *
             * If asked, each address from the set of (re-ordered) target addresses are probed to 
             * check that they are responsive.
             */
            
            prescanner = new NetworkPrescanner(env);
            prescanner->setTimeoutPeriod(env->getTimeoutPeriod());
            
            cout << "--- Start of network pre-scanning ---" << endl;
            timeval prescanningStart, prescanningEnd;
            gettimeofday(&prescanningStart, NULL);
            
            if(kickLogs)
                env->openLogStream("Log_" + newFileName + "_pre-scanning");
            out = env->getOutputStream();
            
            (*out) << "Prescanning with initial timeout..." << endl;
            prescanner->setTargets(targets);
            prescanner->probe();
            (*out) << endl;
            
            if(prescanner->hasUnresponsiveTargets())
            {
                TimeVal timeout2 = env->getTimeoutPeriod() * 2;
                (*out) << "Second opinion with twice the timeout (" << timeout2 << ")..." << endl;
                prescanner->setTimeoutPeriod(timeout2);
                prescanner->reloadUnresponsiveTargets();
                prescanner->probe();
                (*out) << endl;
            }
            else
            {
                (*out) << "All probed IPs were responsive.\n" << endl;
            }
            
            if(kickLogs)
                env->closeLogStream();

            cout << "--- End of network pre-scanning (" << getCurrentTimeStr() << ") ---" << endl;
            gettimeofday(&prescanningEnd, NULL);
            unsigned long prescanningElapsed = prescanningEnd.tv_sec - prescanningStart.tv_sec;
            double successRate = ((double) env->getTotalSuccessfulProbes() / (double) env->getTotalProbes()) * 100;
            size_t nbResponsiveIPs = env->getIPTable()->getTotalIPs();
            cout << "Elapsed time: " << elapsedTimeStr(prescanningElapsed) << endl;
            cout << "Total amount of probes: " << env->getTotalProbes() << endl;
            cout << "Total amount of successful probes: " << env->getTotalSuccessfulProbes();
            cout << " (" << successRate << "%)" << endl;
            cout << "Total amount of discovered responsive IPs: " << nbResponsiveIPs << "\n" << endl;
            env->resetProbeAmounts();

            delete prescanner;
            prescanner = NULL;
            
            // Gets the responsive targets
            targets = parser->getResponsiveTargets();
        }
        
        // Parser is no longer needed
        delete parser;
        parser = NULL;
        
        /*
         * PARIS TRACEROUTE
         *
         * Launches several threads to conduct Paris traceroute measurement towards each target IP.
         *
         * The methodology is identical to what can be found in the prepare() method of the 
         * ClassicGrower class in TreeNET "Arborist" v3.0.
         */
        
        cout << "--- Start of traceroute ---" << endl;
        timeval tracerouteStart, tracerouteEnd;
        gettimeofday(&tracerouteStart, NULL);
        
        if(kickLogs)
            env->openLogStream("Log_" + newFileName + "_traceroute");
        out = env->getOutputStream();

        (*out) << "Computing route towards each target IP...\n" << endl;
        
        // Size of the thread array
        if((unsigned long) targets.size() > (unsigned long) nbThreads)
            nbTasks = nbThreads;
        else
            nbTasks = (unsigned short) targets.size();
        
        // Creates thread(s)
        tracerouteTasks = new Thread*[nbTasks];
        for(unsigned short i = 0; i < nbTasks; i++)
            tracerouteTasks[i] = NULL;
        
        while(targets.size() > 0)
        {
            unsigned short range = DirectProber::DEFAULT_UPPER_SRC_PORT_ICMP_ID;
            range -= DirectProber::DEFAULT_LOWER_SRC_PORT_ICMP_ID;
            range /= nbTasks;
            
            for(unsigned short i = 0; i < nbTasks && targets.size() > 0; i++)
            {
                InetAddress curTarget = targets.front();
                targets.pop_front();
                
                unsigned short lowBound = (i * range);
                unsigned short upBound = lowBound + range - 1;
                
                Runnable *task = NULL;
                try
                {
                    task = new ParisTracerouteTask(env, 
                                                   curTarget, 
                                                   DirectProber::DEFAULT_LOWER_SRC_PORT_ICMP_ID + lowBound, 
                                                   DirectProber::DEFAULT_LOWER_SRC_PORT_ICMP_ID + upBound, 
                                                   DirectProber::DEFAULT_LOWER_DST_PORT_ICMP_SEQ, 
                                                   DirectProber::DEFAULT_UPPER_DST_PORT_ICMP_SEQ);

                    tracerouteTasks[i] = new Thread(task);
                }
                catch(StopException &se)
                {
                    throw StopException();
                }
                catch(SocketException &se)
                {
                    throw StopException();
                }
                catch(ThreadException &te)
                {
                    (*out) << "Unable to create more threads." << endl;
                
                    delete task;
                    
                    throw StopException();
                }
            }

            // Launches thread(s) then waits for completion
            for(unsigned short i = 0; i < nbTasks; i++)
            {
                if(tracerouteTasks[i] != NULL)
                {
                    tracerouteTasks[i]->start();
                    Thread::invokeSleep(env->getProbeThreadDelay());
                }
            }
            
            for(unsigned short i = 0; i < nbTasks; i++)
            {
                if(tracerouteTasks[i] != NULL)
                {
                    tracerouteTasks[i]->join();
                    delete tracerouteTasks[i];
                    tracerouteTasks[i] = NULL;
                }
            }
            
            if(env->isStopping())
                break;
        }
        
        delete[] tracerouteTasks;
        
        /*
         * If we are in laconic display mode, we add a line break before the next message to keep 
         * the display airy enough.
         */
        
        if(displayMode == ToolEnvironment::DISPLAY_MODE_LACONIC)
            (*out) << "\n";
        
        if(env->isStopping())
        {
            throw StopException();
        }
        
        if(kickLogs)
            env->closeLogStream();
        
        cout << "--- End of traceroute (" << getCurrentTimeStr() << ") ---" << endl;
        gettimeofday(&tracerouteEnd, NULL);
        unsigned long tracerouteElapsed = tracerouteEnd.tv_sec - tracerouteStart.tv_sec;
        double successRate = ((double) env->getTotalSuccessfulProbes() / (double) env->getTotalProbes()) * 100;
        cout << "Elapsed time: " << elapsedTimeStr(tracerouteElapsed) << endl;
        cout << "Total amount of probes: " << env->getTotalProbes() << endl;
        cout << "Total amount of successful probes: " << env->getTotalSuccessfulProbes();
        cout << " (" << successRate << "%)\n" << endl;
        env->resetProbeAmounts();
        env->recordRouteStepsInDictionnary();
        env->sortTraces();
        
        // Route repairment and analysis
        cout << "--- Start of route analysis and improvement ---" << endl;
        timeval analysisStart, analysisEnd;
        gettimeofday(&analysisStart, NULL);
        
        if(kickLogs)
            env->openLogStream("Log_" + newFileName + "_route_analysis");
        out = env->getOutputStream();
        
        repairer = new RouteRepairer(env);
        repairer->repair();
        delete repairer;
        repairer = NULL;
        
        (*out) << endl;
        
        postProcessor = new RoutePostProcessor(env);
        postProcessor->process();
        delete postProcessor;
        postProcessor = NULL;
        
        if(kickLogs)
            env->closeLogStream();
        
        cout << "--- End of route analysis (" << getCurrentTimeStr() << ") ---" << endl;
        gettimeofday(&analysisEnd, NULL);
        unsigned long analysisElapsed = analysisEnd.tv_sec - analysisStart.tv_sec;
        cout << "Elapsed time: " << elapsedTimeStr(analysisElapsed) << endl;
        unsigned int totalProbesAnalysis = env->getTotalProbes();
        if(totalProbesAnalysis > 0)
        {
            successRate = ((double) env->getTotalSuccessfulProbes() / (double) env->getTotalProbes()) * 100;
            cout << "Total amount of additionnal probes: " << totalProbesAnalysis << endl;
            cout << "Total amount of successful probes: " << env->getTotalSuccessfulProbes();
            cout << " (" << successRate << "%)" << endl;
        }
        env->resetProbeAmounts();
        
        // Outputs the traces and repairs (if any)
        env->outputTracesMeasured(newFileName + ".traces");
        cout << "\nObtained traces have been saved in an output file ";
        cout << newFileName << ".traces.\n" << flush;
        
        if(env->hasPostProcessedTraces())
        {
            env->outputTracesPostProcessed(newFileName + ".post-processed");
            cout << "Post-processed traces have been saved in an output file ";
            cout << newFileName << ".post-processed.\n" << flush;
        }
        
        if(env->hasRouteRepairs())
        {
            env->outputRouteRepairs(newFileName + ".repair");
            cout << "Route repairs have been saved in an output file ";
            cout << newFileName << ".repair.\n" << flush;
        }
        
        // Second opinion traceroute
        targets = env->listProblematicTargets();
        if(bisTraces > 0 && targets.size() > 0)
        {
            cout << "\n--- Start of second opinion traceroute ---" << endl;
            timeval tracerouteBisStart, tracerouteBisEnd;
            gettimeofday(&tracerouteBisStart, NULL);
            
            if(kickLogs)
                env->openLogStream("Log_" + newFileName + "_traceroute_bis");
            out = env->getOutputStream();

            (*out) << "Re-computing route with stretched IPs and/or cycles..." << endl;
            
            for(unsigned short i = 0; i < bisTraces; i++)
            {
                env->incBisTracesCounter();
                (*out) << "\nOpinion n°" << (i + 2) << "..." << endl;
                
                list<InetAddress> clonedTargets(targets);
            
                // Size of the thread array
                if((unsigned long) clonedTargets.size() > (unsigned long) nbThreads)
                    nbTasks = nbThreads;
                else
                    nbTasks = (unsigned short) clonedTargets.size();
                
                // Creates thread(s)
                tracerouteTasks = new Thread*[nbTasks];
                for(unsigned short i = 0; i < nbTasks; i++)
                    tracerouteTasks[i] = NULL;
                
                while(clonedTargets.size() > 0)
                {
                    unsigned short range = DirectProber::DEFAULT_UPPER_SRC_PORT_ICMP_ID;
                    range -= DirectProber::DEFAULT_LOWER_SRC_PORT_ICMP_ID;
                    range /= nbTasks;
                    
                    for(unsigned short i = 0; i < nbTasks && clonedTargets.size() > 0; i++)
                    {
                        InetAddress curTarget = clonedTargets.front();
                        clonedTargets.pop_front();
                        
                        unsigned short lowBound = (i * range);
                        unsigned short upBound = lowBound + range - 1;
                        
                        Runnable *task = NULL;
                        try
                        {
                            task = new ParisTracerouteTask(env, 
                                                           curTarget, 
                                                           DirectProber::DEFAULT_LOWER_SRC_PORT_ICMP_ID + lowBound, 
                                                           DirectProber::DEFAULT_LOWER_SRC_PORT_ICMP_ID + upBound, 
                                                           DirectProber::DEFAULT_LOWER_DST_PORT_ICMP_SEQ, 
                                                           DirectProber::DEFAULT_UPPER_DST_PORT_ICMP_SEQ);

                            tracerouteTasks[i] = new Thread(task);
                        }
                        catch(StopException &se)
                        {
                            throw StopException();
                        }
                        catch(SocketException &se)
                        {
                            throw StopException();
                        }
                        catch(ThreadException &te)
                        {
                            (*out) << "Unable to create more threads." << endl;
                        
                            delete task;
                            
                            throw StopException();
                        }
                    }

                    // Launches thread(s) then waits for completion
                    for(unsigned short i = 0; i < nbTasks; i++)
                    {
                        if(tracerouteTasks[i] != NULL)
                        {
                            tracerouteTasks[i]->start();
                            Thread::invokeSleep(env->getProbeThreadDelay());
                        }
                    }
                    
                    for(unsigned short i = 0; i < nbTasks; i++)
                    {
                        if(tracerouteTasks[i] != NULL)
                        {
                            tracerouteTasks[i]->join();
                            delete tracerouteTasks[i];
                            tracerouteTasks[i] = NULL;
                        }
                    }
                    
                    if(env->isStopping())
                        break;
                }
                
                delete[] tracerouteTasks;
            }
            
            if(kickLogs)
                env->closeLogStream();
            else
                cout << "\n";
            
            cout << "--- End of second opinion traceroute (" << getCurrentTimeStr() << ") ---" << endl;
            gettimeofday(&tracerouteBisEnd, NULL);
            unsigned long tracerouteBisElapsed = tracerouteBisEnd.tv_sec - tracerouteBisStart.tv_sec;
            double successRate = ((double) env->getTotalSuccessfulProbes() / (double) env->getTotalProbes()) * 100;
            cout << "Elapsed time: " << elapsedTimeStr(tracerouteBisElapsed) << endl;
            cout << "Total amount of probes: " << env->getTotalProbes() << endl;
            cout << "Total amount of successful probes: " << env->getTotalSuccessfulProbes();
            cout << " (" << successRate << "%)\n" << endl;
            env->resetProbeAmounts();
            env->sortTraces();
            
            env->outputTracesMeasured(newFileName + ".traces");
            cout << "Updated traces have been saved in ";
            cout << newFileName << ".traces.\n" << flush;
        }
        
        // Fingerprinting (in the sense of "Network Fingerprinting: TTL-Based Router Signatures", Vanaubel et al.)
        cout << "\n--- Start of fingerprinting ---" << endl;
        timeval fingerprintingStart, fingerprintingEnd;
        gettimeofday(&fingerprintingStart, NULL);
        
        if(kickLogs)
            env->openLogStream("Log_" + newFileName + "_fingerprinting");
        
        fingerprintMaker = new FingerprintMaker(env);
        fingerprintMaker->probe();
        delete fingerprintMaker;
        fingerprintMaker = NULL;
        
        if(kickLogs)
            env->closeLogStream();
        else
            cout << "\n";
        
        cout << "--- End of fingerprinting (" << getCurrentTimeStr() << ") ---" << endl;
        gettimeofday(&fingerprintingEnd, NULL);
        unsigned long fingerprintingElapsed = fingerprintingEnd.tv_sec - fingerprintingStart.tv_sec;
        cout << "Elapsed time: " << elapsedTimeStr(fingerprintingElapsed) << endl;
        successRate = ((double) env->getTotalSuccessfulProbes() / (double) env->getTotalProbes()) * 100;
        cout << "Total amount of probes: " << env->getTotalProbes() << endl;
        cout << "Total amount of successful probes: " << env->getTotalSuccessfulProbes();
        cout << " (" << successRate << "%)\n" << endl;
        env->resetProbeAmounts();
        
        // Rate-limit evaluation
        env->listRateLimitedCandidates();
        list<IPTableEntry*> toProbe = env->getIPTable()->getRateLimitedIPs();
        if(toProbe.size() > 0 && RLNbExperiments > 0)
        {
            cout << "--- Start of rate-limit evaluation ---" << endl;
            timeval rateLimitStart, rateLimitEnd;
            gettimeofday(&rateLimitStart, NULL);
            
            if(kickLogs)
                env->openLogStream("Log_" + newFileName + "_rate-limit_analysis");

            for(list<IPTableEntry*>::iterator it = toProbe.begin(); it != toProbe.end(); ++it)
            {
                RLScheduler = new RoundScheduler(env, (*it));
                RLScheduler->start();
                delete RLScheduler;
                RLScheduler = NULL;
            }
            
            if(kickLogs)
                env->closeLogStream();
            
            cout << "--- End of rate-limit evaluation (" << getCurrentTimeStr() << ") ---" << endl;
            gettimeofday(&rateLimitEnd, NULL);
            unsigned long rateLimitElapsed = rateLimitEnd.tv_sec - rateLimitStart.tv_sec;
            cout << "Elapsed time: " << elapsedTimeStr(rateLimitElapsed) << endl;
            successRate = ((double) env->getTotalSuccessfulProbes() / (double) env->getTotalProbes()) * 100;
            cout << "Total amount of probes: " << env->getTotalProbes() << endl;
            cout << "Total amount of successful probes: " << env->getTotalSuccessfulProbes();
            cout << " (" << successRate << "%)" << endl;
            env->resetProbeAmounts();
            
            env->getIPTable()->outputRoundRecords(newFileName + ".rate-limit");
            cout << "Rate-limit evaluation data has been saved in an output file ";
            cout << newFileName << ".rate-limit." << endl;
        }
        
        // Output of the IP dictionnary
        env->getIPTable()->outputDictionnary(newFileName + ".ip");
        cout << "IP dictionnary has been saved in an output file ";
        cout << newFileName << ".ip." << endl;
    }
    catch(StopException e)
    {
        cout << "RTrack is halting now." << endl;
        
        // Emergency save of the traces
        if(env->getNbTraces() > 0)
        {
            env->sortTraces();
            env->outputTracesMeasured("[Stopped] " + newFileName + ".traces");
            cout << "\nTraces have been saved in a file \"[Stopped] "+ newFileName + ".traces\"." << endl;
        }
        
        // Deleting the threads used for traceroute
        if(tracerouteTasks != NULL)
        {
            for(unsigned short i = 0; i < nbTasks; i++)
            {
                if(tracerouteTasks[i] != NULL)
                {
                    delete tracerouteTasks[i];
                    tracerouteTasks[i] = NULL;
                }
            }
            
            delete[] tracerouteTasks;
        }
        
        // Because pointers are set to NULL after deletion, next lines should not cause any issue.
        delete parser;
        delete prescanner;
        delete repairer;
        delete postProcessor;
        delete fingerprintMaker;
        delete RLScheduler;
        delete env;
        return 1;
    }
    
    delete env;
    return 0;
}
