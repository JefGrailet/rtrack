#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Parses a .rate-limit file and plots, for each mentioned IP that has more than two rounds, the 
# distribution of the response ratio (with confidence intervals). The script outputs a different 
# figure for each candidate IP.

import numpy as np
import os
import sys
from math import sqrt
from matplotlib import pyplot as plt
from scipy import stats as ss
from scipy import zeros

if __name__ == "__main__":

    if len(sys.argv) < 3:
        print("Use this command: python RateLimitDistribution.py [.rate-limit file] [dest folder]")
        sys.exit()
    
    rateLimitFile = str(sys.argv[1])
    destFolder = str(sys.argv[2])
    if destFolder.endswith('/'):
        destFolder = destFolder[:-1]
    
    # Parses the .rate-limit file
    if not os.path.isfile(rateLimitFile):
        print(".rate-limit file does not exist")
        sys.exit()

    with open(rateLimitFile) as f:
        rateLimitRaw = f.read().splitlines()
    
    IPs = dict()
    curIP = ""
    curRatios = []
    for i in range(0, len(rateLimitRaw)):
        if " - " in rateLimitRaw[i]:
            splitted1 = rateLimitRaw[i].split(" - ")
            ratios = splitted1[1].split(' ')
            curRatios.append(ratios)
        else:
            if len(curRatios) > 2:
                if curIP not in IPs:
                    IPs[curIP] = curRatios
                else:
                    IPs[curIP].append(curRatios)
        
            curIP = rateLimitRaw[i]
            curRatios = []
    
    # Last one
    if len(curRatios) > 2:
        if curIP not in IPs:
            IPs[curIP] = curRatios
        else:
            IPs[curIP].append(curRatios)
    
    keys = []
    for IP in IPs:
        keys.append(IP)
    keys.sort()
    
    for i in range(0, len(keys)):
        ratios = IPs[keys[i]]
        means = []
        libdegrees = []
        stddevs = []
        for j in range(0, len(ratios)):
            means.append(np.mean(np.array(ratios[j]).astype(np.float), axis=0))
            stddevs.append(np.std(np.array(ratios[j]).astype(np.float), axis=0))
            libdegrees.append(len(ratios[j]))
        
        # Plot
        hfont = {'fontname':'serif',
                 'fontweight':'bold',
                 'fontsize':30}

        hfont2 = {'fontname':'serif',
                  'fontsize':26}
        
        xAxis = np.arange(1, len(means) + 1, 1)
        fig = plt.figure(figsize=(15,9))
        # Optional title
        # plt.title(keys[i], **hfont)
        plt.ylim([0, 105])
        plt.xlim([1, len(means)])
        
        sqrtMeans = np.sqrt(means)
        for j in range(0, len(sqrtMeans)):
            if sqrtMeans[j] == 0:
                sqrtMeans[j] = 1
        
        plt.errorbar(xAxis, 
                     means, 
                     yerr=(ss.t.ppf(0.95, libdegrees) * stddevs) / sqrtMeans, 
                     color='#000000', 
                     linewidth=4, 
                     ecolor='#0000FF', 
                     elinewidth=4, 
                     linestyle='-', 
                     fmt='o', 
                     mew=10)
        
        plt.xticks(np.arange(1, len(means) + 1, 1), **hfont2)
        plt.yticks(np.arange(0, 110, 10), **hfont2)
        ax = plt.axes()
        # Next two lines are for a purely cosmetic gray zone under the curve
        # d = zeros(len(means))
        # ax.fill_between(xAxis, means, d, where=means>=d, interpolate=True, facecolor='#EEEEEE')
        yticks = ax.yaxis.get_major_ticks()
        yticks[0].label1.set_visible(False)
        plt.ylabel('Response rate (%)', **hfont)
        plt.xlabel('Probing round', **hfont)
        plt.grid()

        newPlotName = "RateLimit_" + keys[i].replace('.', '-') + ".pdf"
        plt.savefig(destFolder + "/" + newPlotName)
        plt.close()
        print("Outputted " + newPlotName + " in " + destFolder + ".")
