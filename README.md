This repository contains a tool to detect if a jar file is affected by the critical CVE-2021-44228. The tool does not need to execute the jar file, but will compare against a set of vulnerable hashes for classes within the jar file. 

# Background on CVE-2021-44228
A serious Remote Code Execution vulnerability has been discovered within log4j and version 2.0-beta9 to 2.14 are affected. The vulnerability has been classified as critical, as it affected log4j one of the most used logging libraries for Java. [References](https://thehackernews.com/2021/12/extremely-critical-log4j-vulnerability.html).  

# Why is it important?
Log4j is and has been used in mostly any Java project for logging purporse. Now we need to understand which projects and libraries are actually affected. As of Java's dependency mechanism, an application can also be affected if it `transitively` includes the vulnerable library version. A project `A` includes a library lib  `transitively`, if one of the direct dependecy `B` of `A` has a dependecy to `lib`. A simple test if one is affected can be done using using the maven dependecy tree:

Example: Execute command `mvn dependency:tree` on a maven project. 

```
[INFO] exampleProject:mainProject:jar:0.0.1-SNAPSHOT
[INFO] +- exampleProject:lib-using-log4j:jar:0.0.1-SNAPSHOT:compile
[INFO] |  \- org.apache.logging.log4j:log4j-core:jar:2.14.1:compile
```

This check however, is not sufficient. Java programs are frequently:
* packaged as fatjar or uberjar: All class files (including direct and transitive dependencies) are shipped as a single jar file.
* re-packaged: the originaly package names are changes as of conflicts (this can be done automatically by the compiler)
* rebundled: ...?
* re-compiled: The source code is re-compiled and packaged anew. 

Purely using SHA hashes on the class file level, does not suffice to detect is a library ships with log4j. Therefore, an indepth bytecode inspection is necessary. This is what has been done as part of this project. 

# Precomputed Hashes of Vulnerable Classes

The set of vulnerable hashes for classes has been pre-compute on [Maven Central](https://mvnrepository.com/repos/central) repository. The hashes of the classes do not only contain hashes of the affected files directly vulnerable jars, i.e., log4j in version range [2.0-beta9, 2.14), but also the following artifacts, but also :

* all aritfacts that directly include log4j in any of the vulnerable version
* all artifacts that ship a class that contains a vulnerable hash of log4j in the affected version range
* all artifacts that rebundle a vulnerable class of log4j 
* all artifacts that have a re-compiled class of a class of log4j w in the affected version range

Details on how this information has been computed, see section on [Fingerprinting Technology](#fingerprinting-technology).

# How the script works
1. Extract .class files from .jar file
2. Computes SHA hashes of the class file
3. Match SHA hashes against SHA hashes in our [pre-computed database]() #TODO add link to file.

# Fingerprinting Technology
This tool uses a new bytecode fingerprinting technology for Java that has been invented by Andreas Dann. The basic flow is as follows. 
1. Use the available fix commits [Commit1](https://gitbox.apache.org/repos/asf?p=logging-log4j2.git;h=7fe72d6), [Commit2](https://gitbox.apache.org/repos/asf?p=logging-log4j2.git;h=d82b47c), and [Commit3](https://gitbox.apache.org/repos/asf?p=logging-log4j2.git;h=c77b3cb) to identify which classes are affected.
2. Compute bytecode hashes of the vulnerable classes.
3. Search for other classes on MavenCentral that also contain similar hashes. 

Details on the technology are found in the paper [SootDiff](https://dl.acm.org/doi/10.1145/3315568.3329966). 
