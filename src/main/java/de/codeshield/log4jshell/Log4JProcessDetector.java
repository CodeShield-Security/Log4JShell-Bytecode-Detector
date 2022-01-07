package de.codeshield.log4jshell;

import edu.emory.mathcs.backport.java.util.Collections;
import org.apache.commons.lang.StringUtils;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class Log4JProcessDetector {

  public static void main(String[] args) throws IOException {

    // grep process (works on mac and linux)
    List<String> commands = new ArrayList<String>();
    commands.add("/bin/sh");
    commands.add("-c");
    commands.add("ps -ef | grep java");

    Process process = new ProcessBuilder(commands).start();
    BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
    List<String> lines = new ArrayList<>();
    String line = null;
    while ((line = reader.readLine()) != null) {
      lines.add(line);
    }

    // analyze each output
    for (String outputLine : lines) {

      final List<String> foundJarsOnCp = parsePSOutPutClassPath(outputLine);
      if (!foundJarsOnCp.isEmpty()) {
        for (String jarFile : foundJarsOnCp) {
          try {
            Log4JDetector detector = new Log4JDetector();
            System.out.println("Scanning jar file " + jarFile);
            // detector.run(jarFile);
          } catch (Exception e) {
            System.out.println("Could not scan jar file " + jarFile);
          }
        }

      } else {
        // no classpath arg found
        continue;
      }
    }
  }

  public static List<String> parsePSOutPutClassPath(String outputLine) {
    // search for the "-classpath" parameter

    String searchStr = "-classpath";
    int i = StringUtils.indexOf(outputLine, searchStr);
    if (i == -1) {
      // check if someone used -cp
      searchStr = "-cp";
      i = StringUtils.indexOf(outputLine, searchStr);
    }
    if (i > 0) {
      String cpArgs = outputLine.substring(i + searchStr.length() + 1);

      // scan for jar files
      String[] cpArgsSplit = cpArgs.split(File.pathSeparator);
      final List<String> foundJarsOnCp =
          Arrays.stream(cpArgsSplit)
              .map(x -> StringUtils.substring(x, 0, StringUtils.indexOf(x, ".jar") + 4))
              .collect(Collectors.toList());
      return foundJarsOnCp;
    }

    return Collections.emptyList();
  }
}
