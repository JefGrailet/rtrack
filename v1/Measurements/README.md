# About Measurements/ folder

*By Jean-François Grailet (last edited: June 10, 2017)*

## Overview

This folder contains measurements which were conducted from the PlanetLab testbed with `RTrack` v1.0. Each sub-folder is named after a target Autonomous System (or AS) and contains measurements for that particular AS, with a sub-folder per dataset, denoted by the date at which the measurements for this dataset were  started.

At the root of each AS sub-folder, you should also find a "\[AS number\].txt" file, which contains the IP prefixes which are fed to `RTrack` as the target prefixes of this AS.

Currently, for all datasets, `RTrack` used pre-scanning to ensure collected routes are as complete as possible and lead to responsive IPs.

## Typical target ASes

The next table lists the typical target ASes we measured with `RTrack` and for which we provide our data in this repository.

|   AS    | AS name                  | Type    | Max. amount of IPs |
| :-----: | :----------------------- | :------ | :----------------- |
| AS109   | Cisco Systems            | Stub    | 1,173,760          |
| AS224   | UNINETT                  | Stub    | 1,115,392          |
| AS703   | Verizon Business         | Transit | 863,232            |
| AS5400  | British Telecom          | Transit | 1,385,216          |
| AS5511  | Orange S.A.              | Transit | 911,872            |
| AS6453  | TATA Communications      | Tier-1  | 656,640            |
| AS8928  | Interoute Communications | Transit | 827,904            |
| AS13789 | Internap Network         | Transit | 96,256             |
| AS22652 | Fibrenoire, Inc.         | Transit | 76,288             |
| AS30781 | Jaguar Network           | Transit | 45,312             |
| AS50673 | Serverius Holding        | Transit | 61,696             |

## Composition of a dataset

Each dataset consists of 6 files:

* A route dump (.traces), where routes are given along their respective target (and estimated TTL of the target), with one hop given per line and the character \# used to isolate routes from each other.

* Similarily, a dump of the post-processed routes (.post-processed). Only post-processed routes are provided, i.e., if routes were not post-processed at all they won't appear again in this file (in that case, use the .traces file). The syntax is the same as in the .traces file.

* A dump of the IP dictionnary (.ip), a list of all responsive IPs (either targets, either route hops) with their respective minimum TTL value to reach them from the vantage point. Each IP is also fingerprinted (in the sense of Vanaubel et al., "*Network Fingerprinting: TTL-based Router Signatures*") and IPs involved in routing anomalies or potentially rate-limited are further annotated.

* A .repair file which provides the incomplete route steps (as triplets) which could be fixed by post-processing and how they were fixed.

* A .rate-limit file which provides, for each IP suspected for being rate-limited, a series of response ratios organized as rounds. Each round corresponds to a series of experiments during which the suspect IP was probed with 2^(round number - 1) probes in one second. Each experiment results in a response ratio.

* A last file named "VP.txt" which gives the PlanetLab node from which `RTrack` was run to get the corresponding dataset.

## Notable remarks

* Usually, datasets are *aligned* time-wise, i.e., the date at which measurements started (used to name the folders where you can find the data itself) is the same for all datasets. Most ASes were measured daily during campaigns. However, for 3 ASes (AS224, AS5511 and AS6453), datasets are collected every two days due to the time taken to complete measurements on these particular targets.
