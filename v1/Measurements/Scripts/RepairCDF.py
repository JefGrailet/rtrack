#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Parses .repair files from a bunch of datasets (containing traces towards a set of ASes) to 
# compute a CDF of the confidence ratio for repairments in all RTrack datasets for a given date.

import numpy as np
import os
import sys
from matplotlib import pyplot as plt

if __name__ == "__main__":

    if len(sys.argv) < 4:
        print("Use this command: python RepairCDF.py [ASes file] [year] [date]")
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

    ratios = []
    for i in range(0, len(ASes)):

        filePath = baseFolder + "/" + ASes[i] + "/" + year + "/" + date
        filePath += "/" + ASes[i] + "_" + date + ".repair"
        
        if not os.path.isfile(filePath):
            print(filePath + " does not exist")
            sys.exit()

        with open(filePath) as f:
            repairsRaw = f.read().splitlines()
        
        for j in range(0, len(repairsRaw)):
            if "online" in repairsRaw[j]:
                continue
            splitted = repairsRaw[j].split(" - ")
            ratio = float(splitted[1][:-2])
            ratios.append(ratio)
   
    # Formats the data for the CDF
    ratios.sort()
    xAxisCDF = []
    yAxisCDF = []
    prev = -1
    curIndex = -1
    for j in range(0, len(ratios)):
        if ratios[j] == prev:
            yAxisCDF[curIndex] += 1
        else:
            curIndex += 1
            xAxisCDF.append(ratios[j] / 100)
            if prev == -1:
                yAxisCDF.append(1)
            else:
                yAxisCDF.append(yAxisCDF[curIndex - 1] + 1)
            prev = ratios[j]
    
    for j in range(0, len(yAxisCDF)):
        yAxisCDF[j] = float(yAxisCDF[j]) / len(ratios)
    
    # Plots the CDF
    hfont = {'fontname':'serif',
             'fontweight':'bold',
             'fontsize':32}
    
    hfont2 = {'fontname':'serif',
              'fontsize':26}
    
    fig = plt.figure(figsize=(15,9))
    plt.ylabel('Cumulative distribution', **hfont)
    plt.xlabel('Confidence ratio', **hfont)
    plt.ylim([0,1])
    plt.xlim([0,1])
    plt.plot(xAxisCDF, yAxisCDF, color='#000000', linewidth=3)
    plt.xticks(np.arange(0.1, 1.01, 0.1), **hfont2)
    plt.yticks(np.arange(0, 1.01, 0.1), **hfont2)
    plt.grid()

    plt.savefig("RepairCDF_" + year + "_" + date + ".pdf")
    plt.clf()
