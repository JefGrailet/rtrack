# RTrack, a traceroute extension to discover routing anomalies

*By Jean-François Grailet (last edited: October 14, 2019)*

## Overview

`RTrack` is a `traceroute` extension which purpose is to detect and study routing anomalies along rate-limited interfaces. The anomalies notably include route stretching, the phenomenon of having an interface appearing only once per route at several different hop counts when several routes collected from a same vantage point are considered together. In addition to detecting these issues, `RTrack` also tries to mitigate them through various post-processing phases, which either fix incomplete hops, either produces post-processed routes when possible and necessary. Finally, it also estimes rate-limiting and is able to restrict its targets to responsive IPs found among the original targets through a pre-scanning phase (very similar to the one present in `TreeNET`). All data (original routes, post-processed routes and post-processing data) can be retrieved at the end of the execution.

The name "`RTrack`" can denote several things, as the `R` can substitute for "**r**ate-limit", "**r**oute stretching" or "**r**oute cycling", while the "`Track`" simply recalls its purpose.

`RTrack` is exclusively available for Linux and IPv4. It also comes as provided as a 32-bit application, in order to ensure compatibility with all PlanetLab computers.

## About development

**`RTrack` will no longer get major algorithmical changes. There won't be new datasets as well.**

On a side note, since it needed to be compatible with old environments (e.g. 32-bit machines from the [PlanetLab testbed](https://planet-lab.eu/) running with Fedora 8), `RTrack` is written in an _old-fashioned_ C++, i.e., it doesn't take advantage of the changes brought by C++11 and onwards. This said, after several campaigns run from PlanetLab towards all kinds of target networks, it is safe to assume `RTrack` is unlikely to crash or mismanage memory. It has been, on top of that, been extensively tested with `valgrind` on a local network.

## Version history (lattest version: v1.0)

* **`RTrack` v1.0:** this is the first version of the program made publicly available (in June 2017). It focuses on rate-limiting, route stretching and route cycling. However, it is currently only compatible with the IPv4 protocol.

## Content of this folder

As the names suggest, *v1/* contains all files related to `RTrack` v1.0, including the first measurements collected with it from the PlanetLab testbed. The source code of is available in *v1/Code/*, while measurements are available in *v1/Measurements/*.

## Disclaimer

`RTrack` was written by Jean-François Grailet, currently Ph. D. student at the University of Liège (Belgium) in the Research Unit in Networking (RUN). It re-uses libraries and also parts of the code of `TreeNET`, a subnet-based topology discovery tool from the same author, which is also available in the following repository:

https://github.com/JefGrailet/treenet

Note that `TreeNET` itself is built on top of `ExploreNET`, a subnet discovery tool elaborated and implemented by Dr. Mehmet Engin Tozal (see `TreeNET` repository for more details).

## Contact

**E-mail address:** Jean-Francois.Grailet@uliege.be

**Personal website:** http://www.run.montefiore.ulg.ac.be/~grailet/

Feel free to send me an e-mail if your encounter problems while compiling or running `RTrack`.
