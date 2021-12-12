package de.codeshield.log4jcheck;

import de.codeshield.log4jcheck.data.GAVWithClassifier;
import de.codeshield.log4jcheck.data.VulnerableGavsData;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Set;
import org.apache.maven.model.Dependency;
import org.apache.maven.model.Model;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.apache.maven.project.MavenProject;
import org.codehaus.plexus.util.xml.pull.XmlPullParserException;

public class POMDetector {

  private static final Set<GAVWithClassifier> VULNERABLE_GAV_DATA = VulnerableGavsData
      .readDataFromCSV();

  public static boolean isVulnerablePOM(InputStream inputStream) {
    final MavenXpp3Reader mavenreader = new MavenXpp3Reader();
    final Model model;
    try {
      model = mavenreader.read(inputStream);
      MavenProject mavenProject = new MavenProject(model);

      //Check whether the Maven Project or any of its parents is affected.
      if (isVulnerableProject(mavenProject)) {
        return true;
      }

      //Check if any of the dependencies is affected.
      List dependencies = mavenProject.getDependencies();
      for (Object dependency : dependencies) {
        if (!(dependency instanceof Dependency)) {
          continue;
        }
        Dependency dep = (Dependency) dependency;
        if (VULNERABLE_GAV_DATA.contains(
            new GAVWithClassifier(dep.getGroupId(), dep.getArtifactId(), dep.getVersion(),
                dep.getClassifier()))) {
          return true;
        }
      }
    } catch (IOException e) {
      System.err.println("Failed reading POM file. Continuing analysis.");
    } catch (XmlPullParserException e) {
      System.err.println("Failed parsing POM file. Continuing analysis.");
    }
    return false;
  }


  private static boolean isVulnerableProject(MavenProject mavenProject) {
    if (VULNERABLE_GAV_DATA.contains(
        new GAVWithClassifier(mavenProject.getGroupId(), mavenProject.getArtifactId(),
            mavenProject.getVersion(), ""))) {
      return true;
    }
    MavenProject parent = mavenProject.getParent();
    if (parent != null) {
      return isVulnerableProject(parent);
    }
    return false;
  }
}
