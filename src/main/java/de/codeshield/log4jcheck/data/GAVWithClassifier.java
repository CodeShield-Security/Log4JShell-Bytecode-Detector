package de.codeshield.log4jcheck.data;

import java.util.Objects;

public class GAVWithClassifier {

  private final String groupId;
  private final String artifactId;
  private final String version;
  private final String classifier;

  public GAVWithClassifier(String groupId, String artifactId, String version,
      String classifier) {
    this.groupId = groupId;
    this.artifactId = artifactId;
    this.version = version;
    this.classifier = classifier;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    GAVWithClassifier that = (GAVWithClassifier) o;
    return Objects.equals(groupId, that.groupId) &&
        Objects.equals(artifactId, that.artifactId) &&
        Objects.equals(version, that.version) &&
        Objects.equals(classifier, that.classifier);
  }

  @Override
  public int hashCode() {
    return Objects.hash(groupId, artifactId, version, classifier);
  }
}
