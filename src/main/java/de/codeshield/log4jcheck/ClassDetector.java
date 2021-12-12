package de.codeshield.log4jcheck;

import de.codeshield.log4jcheck.data.VulnerableClassSHAData;
import java.io.IOException;
import java.io.InputStream;
import java.util.Set;
import org.apache.commons.codec.digest.DigestUtils;

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
