/*
 * RoutePostProcessor.h
 *
 *  Created on: May 4, 2017
 *      Author: jefgrailet
 *
 * This class is dedicated to the detection of route stretching and route cycling among routes and 
 * mitigate both phenomenons as much as possible, as they worsen topology mapping and analysis as 
 * observed in the neighborhood inference of TreeNET.
 *
 * Route stretching is the phenomenon of observing a same IP in several routes, but at different 
 * hop counts. This is likely caused by traffic engineering strategies. This problem can hopefully 
 * be mitigated by evaluating the stretch length in order to re-build routes at tree growth such 
 * that a same IP only occurs at a same unique hop count.
 *
 * Route cycling is a rarer phenomenon in which a same interface occurs several times in a 
 * same route, again likely caused by traffic engineering strategies. It can be mitigated too by 
 * removing the route segment that cycles and replacing it with the cycled IP.
 *
 * Route post-processing is 100% offline work. The class is also strongly similar to the class of 
 * the same name in TreeNET, though there is currently no mitigation of the penultimate hop issue 
 * and no consideration of subnet. In particular, not fixing the penultimate hop issue makes sense 
 * because there is no intention of grouping subnets with similar (post-processed) routes which 
 * would be otherwise separated in many neighborhoods. This fix is therefore a trade-off between 
 * route accuracy and alias resolution, but there is no alias resolution in this case.
 */

#ifndef ROUTEPOSTPROCESSOR_H_
#define ROUTEPOSTPROCESSOR_H_

#include "../ToolEnvironment.h"

class RoutePostProcessor
{
public:
    
    RoutePostProcessor(ToolEnvironment *env); // Access to traces and IP table through env
    ~RoutePostProcessor();
    
    void process();
    
private:
    
    ToolEnvironment *env;
    bool printSteps; // To display steps of each route post-processing (slightly verbose mode)
    
    /*
     * Detection of routing anomalies and their mitigation are separated in two private methods 
     * for the sake of clarity.
     */
    
    void detect();
    void mitigate();
    
    /*
     * Additionnal methods to analyze the route of each subnet and what kind of post-processing 
     * each route needs.
     */
    
    void checkForCycles(Trace *t);
    unsigned short countCycles(Trace *t, unsigned short *longest);
    
    bool needsPostProcessing(Trace *t);
    bool needsCyclingMitigation(Trace *t);
    bool needsStretchingMitigation(Trace *t);
    
    bool hasCycle(RouteInterface *route, unsigned short size);
    bool hasStretch(RouteInterface *route, unsigned short size);
    
    /*
     * Method to find the route prefix of the soonest occurrence (in TTL) of a stretched route 
     * hop among all routes. The size of that prefix is passed by pointer.
     */
    
    RouteInterface *findPrefix(InetAddress stretched, unsigned short *size);
};

#endif /* ROUTEPOSTPROCESSOR_H_ */
