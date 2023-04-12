import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.spec.DHParameterSpec;

public class setup {
  public static void main(String[] argv) throws Exception {
    // choosing a password for Bob - atleast 6 alphanumeric characters
    String password = "CSCI368";

    // hash password using SHA-1 hash function
    String hashedPassword = hash(password);
    
    // get Diffie Hellman parameters
    BigInteger[] pg = dhGenerator();
    
    // output (p, g, H(PW)) to file
    outputFile(pg[0], pg[1], hashedPassword);
  }
  
  // hash Bob's password using SHA-1 hash function
  private static String hash(String password) {
    try {
        // getInstance() method is called with algorithm SHA-1
        MessageDigest md = MessageDigest.getInstance("SHA-1");

        // digest() method is called to calculate message digest of the password returned as array of byte
        byte[] messageDigest = md.digest(password.getBytes());

        // convert byte array into signum representation where the value '1' indicates that the BigInteger is positive
        BigInteger no = new BigInteger(1, messageDigest);

        // convert message digest into hex value
        String hashtext = no.toString(16);

        // add preceding 0s to make it 32 bit
        while (hashtext.length() < 32) {
            hashtext = "0" + hashtext;
        }

        // return the hashtext(H(PW))
        return hashtext;
    } catch (NoSuchAlgorithmException e) { // for specifying wrong message digest algorithms
        throw new RuntimeException(e);
    }
  }

  // generate DH parameters
  private static BigInteger[] dhGenerator() throws Exception {
    // creating the object of AlgorithmParameterGenerator and getting instance using getInstance() method
    AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");

    // initializing the AlgorithmParameterGenerator with 1024 using initialize() method
    paramGen.init(1024);

    // generating the Parameters using generateParameters() method
    AlgorithmParameters params = paramGen.generateParameters();
    DHParameterSpec dhSpec = (DHParameterSpec) params.getParameterSpec(DHParameterSpec.class);
    
    // extract p and g values
    BigInteger p = dhSpec.getP();
    BigInteger g = dhSpec.getG();

    BigInteger[] pg = new BigInteger[2];
    pg[0] = p;
    pg[1] = g;

    return pg;
  }

  // write values to file
  private static void outputFile(BigInteger p, BigInteger g, String hashPassword) {
    // creating new text file
    try {
        // new file
        File file = new File(".\\Alice\\dhparams.txt");
        if (file.createNewFile()) {
            // log action in console
            System.out.println("" + file.getName() + " has been created.");
        } else {
            // log error in console
            System.out.println("File already exists.");
        }
    } catch (IOException e) {
        // log error in console
        System.out.println("An error has occurred.");
        e.printStackTrace();
    }

    // write to file
    try {
        // file writer
        FileWriter writer = new FileWriter(".\\Alice\\dhparams.txt");

        // writing to file
        writer.write(p.toString() + "\n" + g.toString() + "\n" + hashPassword); // converts p and g from BigInteger to String objects in base 10
        writer.close(); // close file writer

        // log action in console
        System.out.println("Successfully written to file.");
    } catch (IOException e) {
        // log error in console
        System.out.println("An error has occurred.");
        e.printStackTrace();
    }
  }
}