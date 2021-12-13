package de.codeshield.log4jshell;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import org.junit.Test;

public class Log4JDetectorTests {

  @Test
  public void checkVulnerables() throws IOException, URISyntaxException {
    assertTrue(checkResourceFile("/en16931-xml-validator-2.0.0-b2-jar-with-dependencies.jar"));
    assertTrue(checkResourceFile("/log4j-core-2.12.1.jar"));
    assertTrue(checkResourceFile("/log4j-core-2.14.1.jar"));
  }

  @Test
  public void checkSecure() throws IOException, URISyntaxException {
    assertFalse(checkResourceFile("/spring-boot-2.5.7.jar"));
    assertFalse(checkResourceFile("/log4j-core-2.15.0.jar"));
  }

  private boolean checkResourceFile(String url) throws IOException, URISyntaxException {
    URL resource = Log4JDetectorTests.class.getResource(url);

    Log4JDetector detector = new Log4JDetector();
    return detector.run(new File(resource.toURI()).getAbsolutePath());
  }
}
