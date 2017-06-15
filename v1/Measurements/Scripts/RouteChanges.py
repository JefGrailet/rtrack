#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Parses a series of .traces files to list the IPs affected by stretching/cycling, count their 
# occurrences and see how they are consistent, TTL-wise, on long term (i.e., on several datasets 
# collected at different dates). "Consistent" here means that the IP is found at the same TTL in 
# a route of the same length in each dataset, for the same respective target IP.

import numpy as np
import os
import sys
from matplotlib import pyplot as plt

if __name__ == "__main__":

    if len(sys.argv) < 4:
        print("Use this command: python RouteChanges.py [ASes file] [year] [list of dates (separated by ,)]")
        sys.exit()
    
    ASFilePath = str(sys.argv[1])
    year = str(sys.argv[2])
    datesList = str(sys.argv[3])
    
    # Parses AS file
    if not os.path.isfile(ASFilePath):
        print("AS file does not exist.")
        sys.exit()

    with open(ASFilePath) as f:
        ASesRaw = f.read().splitlines()
        
    # For this particular file, we do not class by type. We remove the :[type] part.
    ASes = []
    for i in range(0, len(ASesRaw)):
        splitted = ASesRaw[i].split(':')
        ASes.append(splitted[0])
    
    dates = datesList.split(',')
    if len(dates) <= 1:
        print("You must provide at least two dates.")
        sys.exit()
    
    baseFolder = "/path/to/the/datasets/" # TODO: put your own dataset folder here!
    
    ratios1 = []
    ratios2 = []
    ratios3 = []
    ratios4 = []
    for i in range(0, len(ASes)):
        traces = dict()
        firstDay = set()
        bisTraces = dict()
        stretchedIPs = dict()
        cyclingIPs = dict()
        stretchedIPsConsLT = dict()
        cyclingIPsConsLT = dict()
        stretchedIPsConsST = dict()
        cyclingIPsConsST = dict()
        
        # Parses each date for the given AS
        for j in range(0, len(dates)):
            filePath = baseFolder + "/" + ASes[i] + "/" + year + "/" + dates[j]
            filePath += "/" + ASes[i] + "_" + dates[j] + ".traces"
            
            if not os.path.isfile(filePath):
                print(filePath + " does not exist")
                sys.exit()

            with open(filePath) as f:
                tracesRaw = f.read().splitlines()
            
            # Parse the traces
            curTarget = ""
            curTrace = []
            bisTrace = False
            for k in range(0, len(tracesRaw)):
                # New trace
                if tracesRaw[k] == '#' or k == len(tracesRaw) - 1:
                    if k == 0:
                        continue
                    if not bisTrace:
                        if j == 0:
                            if curTarget not in firstDay:
                                firstDay.add(curTarget)
                        if curTarget not in traces:
                            traces[curTarget] = []
                            traces[curTarget].append(curTrace)
                        else:
                            traces[curTarget].append(curTrace)
                    elif j == 0:
                        if curTarget not in bisTraces:
                            bisTraces[curTarget] = []
                            bisTraces[curTarget].append(curTrace)
                        else:
                            bisTraces[curTarget].append(curTrace)
                    curTrace = []
                    curTarget = ""
                    bisTrace = False
                # Parses content of the trace
                else:
                    # Target IP
                    if tracesRaw[k].startswith("Target: "):
                        targetSplitted = tracesRaw[k].split(' ')
                        curTarget = targetSplitted[1]
                        if "opinion n" in tracesRaw[k]:
                            bisTrace = True
                    # Hops (also initializes stretched/cycling IPs dictionnaries)
                    elif "TTL" not in tracesRaw[k] and "Unreachable" not in tracesRaw[k]:
                        hopSplitted = tracesRaw[k].split(" - ")
                        curTrace.append(hopSplitted[1])
                        if j == 0: # Only for first dataset in the list!
                            if "Cycle" in hopSplitted[1]:
                                furtherSplitted = hopSplitted[1].split(" ")
                                cyclingIP = furtherSplitted[0]
                                if cyclingIP not in cyclingIPs:
                                    cyclingIPs[cyclingIP] = 0
                                    cyclingIPsConsLT[cyclingIP] = 0
                                    cyclingIPsConsST[cyclingIP] = 0
                            if "Stretched" in hopSplitted[1]:
                                furtherSplitted = hopSplitted[1].split(" ")
                                stretchedIP = furtherSplitted[0]
                                if stretchedIP not in stretchedIPs:
                                    stretchedIPs[stretchedIP] = 0
                                    stretchedIPsConsLT[stretchedIP] = 0
                                    stretchedIPsConsST[stretchedIP] = 0
        
        # Checks each trace
        for target in firstDay:
            initialTrace = traces[target][0]

            # Checks each hop of the trace
            for j in range(0, len(initialTrace)):
                stretched = False
                cycle = False
                if "Stretched" in initialTrace[j] or initialTrace[j] in stretchedIPs:
                    stretched = True
                elif "Cycle" in initialTrace[j] or initialTrace[j] in cyclingIPs:
                    cycle = True
                
                # If hop is a IP affected by stretching or cycling
                if stretched or cycle:
                    lineSplitted = initialTrace[j].split(" ")
                    IP = lineSplitted[0]
                    
                    # Increments the counter of the IP in the (1st dataset) dictionnary
                    if stretched:
                        stretchedIPs[IP] += 1
                    else:
                        cyclingIPs[IP] += 1
                    
                    # (LT) Checks that the IP appears at the same TTL in next traces (same target)
                    consistent = True
                    for k in range(1, len(traces[target])):
                        if len(traces[target][k]) != len(initialTrace):
                            consistent = False
                            break
                        lineSplittedBis = traces[target][k][j].split(" ")
                        IPBis = lineSplittedBis[0]
                        if IP != IPBis:
                            consistent = False
                            break
                    
                    # (LT) If it is truly consistent, we increment the IP in the right dictionnary
                    if consistent:
                        if stretched:
                            stretchedIPsConsLT[IP] += 1
                        else:
                            cyclingIPsConsLT[IP] += 1
                    
                    # (ST) Checks that the IP appears at the same TTL in next traces (same target)
                    consistent = True
                    if target in bisTraces:
                        for k in range(0, len(bisTraces[target])):
                            if len(bisTraces[target][k]) != len(initialTrace):
                                consistent = False
                                break
                            lineSplittedBis = bisTraces[target][k][j].split(" ")
                            IPBis = lineSplittedBis[0]
                            if IP != IPBis:
                                consistent = False
                                break
                    
                    # (ST) If it is truly consistent, we increment the IP in the right dictionnary
                    if consistent:
                        if stretched:
                            stretchedIPsConsST[IP] += 1
                        else:
                            cyclingIPsConsST[IP] += 1
        
        # Counts the total of occurrences and the total of consistent occurrences
        totalOccStretched = 0
        totalOccStretchedConsLT = 0
        totalOccStretchedConsST = 0
        for IP in stretchedIPs:
            totalOccStretched += stretchedIPs[IP]
            totalOccStretchedConsLT += stretchedIPsConsLT[IP]
            totalOccStretchedConsST += stretchedIPsConsST[IP]
        
        totalOccCycling = 0
        totalOccCyclingConsLT = 0
        totalOccCyclingConsST = 0
        for IP in cyclingIPs:
            totalOccCycling += cyclingIPs[IP]
            totalOccCyclingConsLT += cyclingIPsConsLT[IP]
            totalOccCyclingConsST += cyclingIPsConsST[IP]
        
        r1 = float(totalOccStretchedConsLT) / float(totalOccStretched) * 100
        r2 = float(totalOccCyclingConsLT) / float(totalOccCycling) * 100
        r3 = float(totalOccStretchedConsST) / float(totalOccStretched) * 100
        r4 = float(totalOccCyclingConsST) / float(totalOccCycling) * 100
        
        print(ASes[i] + ":")
        print("Consistent stretched IPs (LT): " + str(totalOccStretchedConsLT) + " / " + str(totalOccStretched) + " (" + str('%.3f' % r1) + "%)")
        print("Consistent cycling IPs (LT): " + str(totalOccCyclingConsLT) + " / " + str(totalOccCycling) + " (" + str('%.3f' % r2) + "%)")
        print("Consistent stretched IPs (ST): " + str(totalOccStretchedConsST) + " / " + str(totalOccStretched) + " (" + str('%.3f' % r3) + "%)")
        print("Consistent cycling IPs (ST): " + str(totalOccCyclingConsST) + " / " + str(totalOccCycling) + " (" + str('%.3f' % r4) + "%)")
        
        ratios1.append(r1)
        ratios2.append(r2)
        ratios3.append(r3)
        ratios4.append(r4)
    
    # Plots in a bar chart the ratios
    ind = np.arange(len(ASes))
    width = 0.2
    
    fig = plt.figure(figsize=(15,9))
    ax = fig.add_subplot(111)
    rects1 = ax.bar(ind + 0.1 + width * 2, ratios1, width, color='#7F7F7F')
    rects2 = ax.bar(ind + 0.1 + width * 3, ratios2, width, color='#333333')
    rects3 = ax.bar(ind + 0.1, ratios3, width, color='#EEEEEE')
    rects4 = ax.bar(ind + 0.1 + width, ratios4, width, color='#BDBDBD')
    ax.autoscale(tight=True)
    ax.yaxis.grid(True)
    
    hfont = {'fontname':'serif',
             'fontweight':'bold',
             'fontsize':32}
    
    hfont2 = {'fontname':'serif',
              'fontsize':26}
    
    plt.ylabel('Consistent occurrences (%)', **hfont)
    plt.xlabel('AS Index', **hfont)
    plt.ylim([0,100])
    plt.xlim([0,len(ASes)])
    plt.xticks(ind + 0.5, range(1,12,1), **hfont2)
    plt.yticks(np.arange(0, 101, 10), **hfont2)
    
    plt.rc('font', family='serif', size=17)
    plt.legend((rects3[0], rects4[0], rects1[0], rects2[0]), 
               ('Stretched (ST)', 'Cycling (ST)', 'Stretched (LT)', 'Cycling (LT)'), 
               bbox_to_anchor=(0, 1.02, 1.0, .102), 
               loc=3,
               ncol=4, 
               mode="expand", 
               borderaxespad=0.)

    plt.savefig("RouteChanges_" + year + "_" + dates[0] + "_" + dates[len(dates) - 1] + ".pdf")
    plt.clf()
