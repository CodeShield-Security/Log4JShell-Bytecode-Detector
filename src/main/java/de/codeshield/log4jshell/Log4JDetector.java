package de.codeshield.log4jshell;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.DirectoryFileFilter;
import org.apache.commons.io.filefilter.RegexFileFilter;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Collection;
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
  private static final String JAR_FILE = ".jar";
  private static final String WAR_FILE = ".war";

  public static void main(String[] args) throws IOException {
    System.out.println("Analysing " + args[0]);
    File inputJarFile = new File(args[0]);
    if (!inputJarFile.exists()) {
      System.err.println(
          "The file path " + args[0] + " does not exist. Ensure it is an absolute file paths");
      return;
    }
    Log4JDetector detector = new Log4JDetector();
    detector.run(args[0]);
  }

  // Taken from
  // https://stackoverflow.com/questions/981578/how-to-unzip-files-recursively-in-java/7108813#7108813
  public static String extractFolder(String zipFile) throws IOException {
    int buffer = 2048;
    File file = new File(zipFile);
    String newPath = zipFile.substring(0, zipFile.length() - 4);

    try (JarFile zip = new JarFile(file)) {

      new File(newPath).mkdir();
      Enumeration<JarEntry> zipFileEntries = zip.entries();

      // Process each entry
      while (zipFileEntries.hasMoreElements()) {
        // grab a zip file entry
        JarEntry entry = zipFileEntries.nextElement();
        String currentEntry = entry.getName();
        File destFile = new File(newPath, currentEntry);
        File destinationParent = destFile.getParentFile();

        // create the parent directory structure if needed
        destinationParent.mkdirs();

        if (!entry.isDirectory()) {
          BufferedInputStream is = new BufferedInputStream(zip.getInputStream(entry));
          int currentByte;
          // establish buffer for writing file
          byte[] data = new byte[buffer];

          // write the current file to disk
          FileOutputStream fos = new FileOutputStream(destFile);
          try (BufferedOutputStream dest = new BufferedOutputStream(fos, buffer)) {

            // read and write until last byte is encountered
            while ((currentByte = is.read(data, 0, buffer)) != -1) {
              dest.write(data, 0, currentByte);
            }
            dest.flush();
            is.close();
          }
        }

        if (currentEntry.endsWith(WAR_FILE) || currentEntry.endsWith(JAR_FILE)) {
          // found a zip file, try to open
          extractFolder(destFile.getAbsolutePath());
        }
      }
    }
    return newPath;
  }

  public boolean run(String pathToJarFile) throws IOException {
    String folder = extractFolder(pathToJarFile);
    Collection<File> pomFiles =
        FileUtils.listFiles(
            new File(folder), new RegexFileFilter("^(pom.xml)"), DirectoryFileFilter.DIRECTORY);
    boolean isVulnerable = false;
    for (File pomFile : pomFiles) {
      try (FileInputStream is = new FileInputStream(pomFile)) {
        // Check if a pom file matches one of the pre-computed groupId:artifactId:version
        if (POMDetector.isVulnerablePOM(is)) {
          isVulnerable = true;
          System.err.println("CVE-2021-44228 found declared as dependency in " + pomFile);
        }
      }
    }
    Collection<File> classFiles =
        FileUtils.listFiles(
            new File(folder), new RegexFileFilter(".*.class$"), DirectoryFileFilter.DIRECTORY);

    for (File classFile : classFiles) {
      try (FileInputStream is = new FileInputStream(classFile)) {
        // Check if a class file matches one of the pre-computed vulnerable SHAs.
        if (ClassDetector.isVulnerableClass(is)) {
          isVulnerable = true;
          System.err.println("CVE-2021-44228 found in class file " + classFile);
        }
      }
    }
    if (!isVulnerable) {
      System.out.println("Jar file not affected by CVE-2021-44228!");
    }
    FileUtils.deleteDirectory(new File(folder));
    return isVulnerable;
  }
}
