package de.codeshield.log4jshell;

import de.codeshield.log4jshell.data.VulnerableClassSHAData;
import org.apache.commons.codec.digest.DigestUtils;

import java.io.IOException;
import java.io.InputStream;
import java.util.Set;

public class ClassDetector {

  private static Set<String> VULNERABLE_CLASS_SHAS = VulnerableClassSHAData.readDataFromCSV();

  public static boolean isVulnerableClass(InputStream inputStream) {
    return VULNERABLE_CLASS_SHAS.contains(getSha256DigestFor(inputStream));
  }

  private static String getSha256DigestFor(InputStream key) {
    String digest = null;
    try {
      digest = new DigestUtils(DigestUtils.getSha256Digest()).digestAsHex(key);
    } catch (IOException e) {
      System.out.println("Unable to compute SHA for class. Continuing analysis.");
    }
    return digest;
  }
}
