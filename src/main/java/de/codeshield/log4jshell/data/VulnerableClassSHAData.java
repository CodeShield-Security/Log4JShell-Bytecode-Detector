package de.codeshield.log4jshell.data;

import com.opencsv.CSVReader;
import com.opencsv.exceptions.CsvException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashSet;
import java.util.Set;

public class VulnerableClassSHAData {

  private static final String CSV_DATA = "/VulnerableClassSHAs.csv";

  public static Set<String> readDataFromCSV() {
    Set<String> vulnerableSHAs = new HashSet<>();
    InputStream resource = VulnerableClassSHAData.class.getResourceAsStream(CSV_DATA);
    try (BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(resource))) {
      CSVReader csvReader = new CSVReader(bufferedReader);
      for (String[] vulnerableClassSha : csvReader.readAll()) {
        vulnerableSHAs.add(vulnerableClassSha[1]);
      }
      csvReader.close();
    } catch (IOException e) {
      System.err.println("Error reading CSV file (" + CSV_DATA + ")");
    } catch (CsvException e) {
      System.err.println("Error parsing CSV file (" + CSV_DATA + ")");
    }
    return vulnerableSHAs;
  }
}
