#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Parses .traces files containing routes towards a bunch of ASes to compute the amount of routes 
# affected by stretching, cycling and/or rate-limiting for each dataset.

import numpy as np
import os
import sys
from matplotlib import pyplot as plt

if __name__ == "__main__":

    if len(sys.argv) < 4:
        print("Use this command: python RouteProblems.py [ASes file] [year] [date]")
        sys.exit()
    
    ASFilePath = str(sys.argv[1])
    year = str(sys.argv[2])
    date = str(sys.argv[3])
    
    # Parses AS file
    if not os.path.isfile(ASFilePath):
        print("AS file does not exist")
        sys.exit()

    with open(ASFilePath) as f:
        ASesRaw = f.read().splitlines()
        
    # For this particular file, we do not class by type. We remove the :[type] part.
    ASes = []
    for i in range(0, len(ASesRaw)):
        splitted = ASesRaw[i].split(':')
        ASes.append(splitted[0])

    baseFolder = "/path/to/the/datasets/" # TODO: put your own dataset folder here!

    ratios1 = []
    ratios2 = []
    ratios3 = []
    for i in range(0, len(ASes)):
        filePath = baseFolder + "/" + ASes[i] + "/" + year + "/" + date
        filePath += "/" + ASes[i] + "_" + date + ".traces"
        
        if not os.path.isfile(filePath):
            print(filePath + " does not exist")
            sys.exit()

        with open(filePath) as f:
            tracesRaw = f.read().splitlines()

        # Parse the traces
        traces = dict()
        curTarget = ""
        curTrace = []
        bisTrace = False
        for j in range(0, len(tracesRaw)):
            # New trace
            if tracesRaw[j] == '#' or j == len(tracesRaw) - 1:
                if j == 0:
                    continue
                if not bisTrace:
                    if curTarget not in traces:
                        traces[curTarget] = []
                        traces[curTarget].append(curTrace)
                    else:
                        traces[curTarget].append(curTrace)
                curTrace = []
                curTarget = ""
                bisTrace = False
            # Parses content of the trace
            elif bisTrace:
                continue
            else:
                # Target IP
                if tracesRaw[j].startswith("Target: "):
                    targetSplitted = tracesRaw[j].split(' ')
                    curTarget = targetSplitted[1]
                    if "opinion n" in tracesRaw[j]:
                        bisTrace = True
                        continue
                # Hops
                elif "TTL" not in tracesRaw[j] and "Unreachable" not in tracesRaw[j]:
                    hopSplitted = tracesRaw[j].split(" - ")
                    curTrace.append(hopSplitted[1])
        
        nTraces = float(len(traces))
        nbWithRateLimited = 0
        nbWithStretches = 0
        nbWithCycles = 0
        for target in traces:
            curTrace = traces[target][0]
            isRateLimited = False
            hasStretches = False
            hasCycles = False
            for j in range(0, len(curTrace)):
                if not isRateLimited and ("Limited" in curTrace[j] or "Repaired-" in curTrace[j]):
                    isRateLimited = True
                    nbWithRateLimited += 1
                elif not hasStretches and "Stretched" in curTrace[j]:
                    hasStretches = True
                    nbWithStretches += 1
                elif not hasCycles and "Cycle" in curTrace[j]:
                    hasCycles = True
                    nbWithCycles += 1
        
        ratioRateLimited = (float(nbWithRateLimited) / nTraces) * 100
        ratioWithStretches = (float(nbWithStretches) / nTraces) * 100
        ratioWithCycles = (float(nbWithCycles) / nTraces) * 100
        
        print(ASes[i] + ":")
        print("Rate-limited IPs: " + str(nbWithRateLimited) + " (" + str('%.2f' % ratioRateLimited) + "%)")
        print("Stretched IPs: " + str(nbWithStretches) + " (" + str('%.2f' % ratioWithStretches) + "%)")
        print("Cycling IPs: " + str(nbWithCycles) + " (" + str('%.2f' % ratioWithCycles) + "%)")
        
        ratios1.append(ratioRateLimited)
        ratios2.append(ratioWithStretches)
        ratios3.append(ratioWithCycles)
   
    # Plots in a bar chart the ratios
    ind = np.arange(len(ASes))
    width = 0.3
    
    fig = plt.figure(figsize=(15,9))
    ax = fig.add_subplot(111)
    rects1 = ax.bar(ind + 0.05, ratios1, width, color='#EEEEEE')
    rects2 = ax.bar(ind + 0.05 + width, ratios2, width, color='#7D7D7D')
    rects3 = ax.bar(ind + 0.05 + width * 2, ratios3, width, color='#333333')
    ax.autoscale(tight=True)
    ax.yaxis.grid(True)
    
    hfont = {'fontname':'serif',
             'fontweight':'bold',
             'fontsize':26}
    
    hfont2 = {'fontname':'serif',
             'fontsize':20}
    
    plt.ylabel('Ratio (%) of routes', **hfont)
    plt.xlabel('AS Index', **hfont)
    plt.ylim([0,100])
    plt.xlim([0,len(ASes)])
    plt.xticks(ind + 0.5, range(1,12,1), **hfont2)
    plt.yticks(np.arange(0, 101, 10), **hfont2)
    
    plt.rc('font', family='serif', size=15)
    plt.legend((rects1[0], rects2[0], rects3[0]), 
               ('With potentially rate-limited IPs', 'With stretches', 'With cycles'), 
               bbox_to_anchor=(0.05, 1.02, 0.90, .102), 
               loc=3,
               ncol=4, 
               mode="expand", 
               borderaxespad=0.)

    plt.savefig("RouteProblems_" + year + "_" + date + ".pdf")
    plt.clf()
