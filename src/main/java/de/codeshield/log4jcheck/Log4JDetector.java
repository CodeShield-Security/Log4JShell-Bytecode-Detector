package de.codeshield.log4jcheck;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * A simple command line tool that scans a jar file for the CVE-2021-44228 vulnerability that
 * concerns log4j.
 */
public class Log4JDetector {

  private static final String POM_FILE = "pom.xml";
  private static final String CLASS_FILE_NAME = ".class";

  public static void main(String[] args) {
    System.out.println("Analysing "+ args[0]);
    File inputJarFile = new File(args[0]);
    if (!inputJarFile.exists()) {
      System.err.println("The file path " + args[0] + " does not exist. Ensure it is an absolute file paths");
      return;
    }
    Log4JDetector detector = new Log4JDetector();
    detector.run(inputJarFile);
  }

  public boolean run(File pathToJarFile) {
    JarFile jarFile = null;
    boolean isVulnerable = false;
    try {
      jarFile = new JarFile(pathToJarFile);
      Enumeration<JarEntry> entries = jarFile.entries();
      while (entries.hasMoreElements()) {
        JarEntry entry = entries.nextElement();
        //Check pom.xml files if a log4j dependency is declared
        if (entry.getName().endsWith(Log4JDetector.POM_FILE)) {
          if (POMDetector.isVulnerablePOM(jarFile.getInputStream(entry))) {
            isVulnerable = true;
            System.err.println("CVE-2021-44228 found declared as dependency in " + entry);
          }
        }
        //Check if a a class file matches one of the pre-computed vulnerable SHAs.
        if (entry.getName().endsWith(Log4JDetector.CLASS_FILE_NAME)) {
          if (ClassDetector.isVulnerableClass(jarFile.getInputStream(entry))) {
            isVulnerable = true;
            System.err.println("CVE-2021-44228 found in class file " + entry);
          }
        }
      }
    } catch (IOException e) {
      System.err.println("Unable to open JarFile");
    }
    if(!isVulnerable){
      System.out.println("Jar file not affected by CVE-2021-44228!");
    }
    return isVulnerable;
  }


}
