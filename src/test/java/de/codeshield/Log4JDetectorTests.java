package de.codeshield;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import de.codeshield.log4jcheck.Log4JDetector;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Paths;
import org.junit.Test;

public class Log4JDetectorTests
{
    @Test
    public void checkVulnerables() throws IOException {
      assertTrue(checkResourceFile("/en16931-xml-validator-2.0.0-b2-jar-with-dependencies.jar"));
    }

    @Test
    public void checkSecure() throws IOException{
      assertFalse(checkResourceFile("/spring-boot-2.5.7.jar") );
    }


    private boolean checkResourceFile(String url) throws IOException {
      URL resource = Log4JDetectorTests.class.getResource(url);

      Log4JDetector detector = new Log4JDetector();
      return detector.run(Paths.get(resource.getPath()));
    }
}
