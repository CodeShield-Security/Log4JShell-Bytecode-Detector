package de.codeshield.log4jshell.data;

import com.opencsv.CSVReader;
import com.opencsv.exceptions.CsvException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashSet;
import java.util.Set;

public class VulnerableGavsData {

  private static final String CSV_DATA = "/VulnerableGavs.csv";

  public static Set<GAVWithClassifier> readDataFromCSV() {
    InputStream resource = VulnerableGavsData.class.getResourceAsStream(CSV_DATA);
    Set<GAVWithClassifier> vulnerableGavs = new HashSet<>();
    try (BufferedReader bufferedReader =  new BufferedReader(new InputStreamReader(resource))) {
      CSVReader csvReader = new CSVReader(bufferedReader);
      for (String[] dep : csvReader.readAll()) {
        vulnerableGavs.add(new GAVWithClassifier(dep[0], dep[1], dep[2], dep[3]));
      }
      csvReader.close();
    } catch (IOException e) {
      System.err.println("Error reading CSV file ("+CSV_DATA+")");
    } catch (CsvException e) {
      System.err.println("Error parsing CSV file ("+CSV_DATA+")");
    }
    return vulnerableGavs;
  }
}
