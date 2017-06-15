# About Scripts/ folder

*By Jean-François Grailet (last edited: June 15, 2017)*

## Overview

This folder contains some Python scripts one can use to generate figures from the datasets collected by `RTrack` v1.0 from the PlanetLab testbed.

## Content of the folder

* *RateLimitDistribution.py*: given a .rate-limit file and a destination folder, this script parses the rate-limit file and generates a plot for each IP having more than two rounds, showing the response ratio as the round number increases. The plots also feature confidence intervals.

* *RepairCDF.py*: for a given date (as year + date), this script generates the cumulative distribution function (CDF) of the confidence ratio for each replacement of a missing hop in a route by an existing IP using the *two policemen and a drunk* heuristic. It also requires a short text file, such as *AllASes*, listing the datasets to use, denoted by the ASes they target.

* *RouteChanges.py*: for a list of dates (separated by commas) and a year, this script computes the consistency of IPs affected by route cycling and route stretching over time, using the first dataset as a reference. It both computes consistency on short term (ST), using bis traces of the first dataset, and on a longer span of time (LT) by using all datasets, and plots everything in a single figure. It also requires a short text file, such as *AllASes*, listing the datasets to use, denoted by the ASes they target.

* *RouteProblems.py*: for a given date (as year + date), this script computes the ratio of routes, for each dataset, affected by (potential) rate-limiting, route stretching and route cycling, and plots the results into a single figure. It also requires a short text file, such as *AllASes*, listing the datasets to use, denoted by the ASes they target.

## Remarks

* In figures involving datasets, individual datasets are denoted by an index. This index corresponds to the position of the target AS in the input text file listing them.
