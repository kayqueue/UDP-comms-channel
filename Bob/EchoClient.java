import java.io.IOException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;


public class EchoClient {

  // Port number for the socket
  private static final int PORT_NUMBER = 1234;
  
  private static final Scanner SCANNER = new Scanner(System.in);

  public static void main(String[] args) throws Exception {
    try {
        // Create a new DatagramSocket to receive and send packets
        DatagramSocket socket = new DatagramSocket();
        socket.setSoTimeout(30 * 1000); // 30 seconds timeout
        InetAddress inet = InetAddress.getLocalHost();

        // client asks for password
        String password = "";
        if (password.equals("")) {
            System.out.print("Enter password: ");
            password = SCANNER.nextLine();
        }

        // hash the entered password
        String passwordHash = SHA1_Hash(password);

        /* ESTABLISHING HANDSHAKE */
        // sends connection request to server
        requestConnection(socket, inet, PORT_NUMBER);
        System.out.println("Client is running and listening on port " + PORT_NUMBER + "...\n");

        // await server response and get relevant values - p, ga mod p, gb mod p
        BigInteger[] p_gaModp_gbModp_b = awaitFirstResponse(socket, passwordHash, SCANNER);
        BigInteger p = p_gaModp_gbModp_b[0];
        BigInteger gaModp = p_gaModp_gbModp_b[1];
        BigInteger gbModp = p_gaModp_gbModp_b[2];
        BigInteger b = p_gaModp_gbModp_b[3];

        // compute shared key k
        String sharedKey = getSharedKey(gaModp, b, p);

        // send back E(H(PW), gb mod p) to server
        sendSecondReponse(socket, inet, PORT_NUMBER, passwordHash, gbModp);

        // await server response and get relevant values - K, nonce_a
        String[] k_nonceA_nonceB = awaitSecondResponse(socket, passwordHash);
        String nonce_a = k_nonceA_nonceB[1];
        String nonce_b = k_nonceA_nonceB[2];

        // send back E(K, NonceA + 1, NonceB)
        sendThirdResponse(socket, inet, PORT_NUMBER, sharedKey, nonce_a, nonce_b, passwordHash);

        // await final server response - whether successful of not
        // if successful, client then checks nonce_b + 1
        boolean validNonce = awaitThirdResponse(socket, passwordHash, nonce_b);

        // if nonce is invalid
        if (!validNonce) { 
            socket.close(); // close socket
            SCANNER.close(); // close scanner
            System.err.println("Handshake unsuccessful. Terminating communication channel...\n");
            System.exit(-1);
        } else {
            System.out.println("Handshake is successful! Beginning communication with Host(Alice)...\n");

            while (true) {
                System.out.print("Your message: ");
                String message = SCANNER.nextLine();

                sendMessage(socket, inet, PORT_NUMBER, message, sharedKey, passwordHash);

                receiveMessage(socket, sharedKey);

                // // Array of bytes to store data to be sent
                // byte[] sendData = message.getBytes(StandardCharsets.UTF_8);

                // // DatagramPacket to send data
                // DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, inet, PORT_NUMBER);

                // // Send the data
                // socket.send(sendPacket);

                // if (message.equals("exit")) {
                //     System.out.println("Exiting communication channel...\n");
                //     socket.close(); // terminate socket
                //     SCANNER.close(); // close scanner
                //     System.exit(1);
                //     break; // exit while loop
                // }

                // // Array of bytes to store data received in a packet
                // byte[] receiveData = new byte[1024];
        
                // // DatagramPacket to receive data
                // DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);

                // // Receive data and print it to the console
                // socket.receive(receivePacket);
                // String receiveMessage = new String(receivePacket.getData());
                // System.out.println("Alice: " + receiveMessage);
            }
        }
    } catch (SocketTimeoutException e) {
        SCANNER.close();
        System.err.println("No response from client. Terminating communication channel...\n");
        System.exit(-1);
    } catch (IOException e) {
        e.printStackTrace();
    }
  }

  // hash the entered password using SHA-1 hash function
  private static String SHA1_Hash(String plaintext) {
    try {
        // getInstance() method is called with algorithm SHA-1
        MessageDigest md = MessageDigest.getInstance("SHA-1");

        // digest() method is called to calculate message digest of the password returned as array of byte
        byte[] messageDigest = md.digest(plaintext.getBytes());

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

  // request connection to server
  private static void requestConnection(DatagramSocket socket, InetAddress inet, int PORT_NUMBER) throws Exception {
    try {
        // request connection with the message "Bob"
        String message = "Bob";

        // Array of bytes to store data to be sent
        byte[] sendData = message.getBytes(StandardCharsets.UTF_8);

        // DatagramPacket to send message
        DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, inet, PORT_NUMBER);

        // send the message
        socket.send(sendPacket);
        System.out.println("Sending communication request to Host(Alice)\n");
    } catch (Exception e) {
        e.printStackTrace();
    }
  }

  // first server response message - E(H(PW), p, g, ga mod p)
  private static BigInteger[] awaitFirstResponse(DatagramSocket socket, String passwordHash, Scanner scanner) throws Exception {
    // Array of bytes to store data received in a packet
    byte[] receiveData = new byte[1024];

    // DatagramPacket to receive data
    DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);

    // receive data
    socket.receive(receivePacket);
    System.out.println("Receiving E(H(PW), p, g, ga mod p) from Host(Alice)\n");

    // decrypt received data
    byte[] decryptedMessageBytes = decryptMessage(receivePacket, passwordHash);

    // convert decrypted message in bytes to string value
    String decryptedMessage = new String(decryptedMessageBytes, StandardCharsets.UTF_8);

    // split up the values from the message
    String pwHash = "";
    String p = "";
    String g = "";
    String gaModp = "";

    int commaCount = 0; // using comma as a delimiter in my message
    for (int i = 0; i < decryptedMessage.length(); i++) {
        if (decryptedMessage.charAt(i) == ',') {
            commaCount += 1;
            continue;
        }
        if (commaCount == 0) {
            pwHash += decryptedMessage.charAt(i);
        }
        if (commaCount == 1) {
            if (!pwHash.equals(passwordHash)) {
                socket.close(); // close socket
                scanner.close(); // close scanner
                System.err.println("Wrong password. Terminating communication channel... (Please enter CSCI368 for the password)\n");
                System.exit(-1);
            }
            p += decryptedMessage.charAt(i);
        }
        if (commaCount == 2) {
            g += decryptedMessage.charAt(i);
        }
        if (commaCount == 3 && i < decryptedMessage.length()) {
            gaModp += decryptedMessage.charAt(i);
        }
    }

    BigInteger bigP, bigG, bigGaModp;
    bigP = new BigInteger(p);
    bigG = new BigInteger(g);
    bigGaModp = new BigInteger(gaModp);

    BigInteger[] b_gbModP = generateLog(bigP, bigG);
    BigInteger b = b_gbModP[0];
    BigInteger gbModp = b_gbModP[1];

    BigInteger[] p_gaModp_gaModb_b = new BigInteger[4];
    p_gaModp_gaModb_b[0] = bigP;
    p_gaModp_gaModb_b[1] = bigGaModp;
    p_gaModp_gaModb_b[2] = gbModp;
    p_gaModp_gaModb_b[3] = b;

    return p_gaModp_gaModb_b;
  }

  // generate random 'b' value and compute gb mod p
  private static BigInteger[] generateLog(BigInteger p, BigInteger g) {
    // p = upper limit, 1 = lower limit
    BigInteger lowerLimit = new BigInteger("1");
    BigInteger dummy = p.subtract(lowerLimit);
    Random rand = new Random();
    int len = p.bitLength();
    BigInteger b = new BigInteger(len, rand);

    if (b.compareTo(lowerLimit) < 0)
        b = b.add(lowerLimit);
    if (b.compareTo(dummy) >= 0)
        b = b.mod(dummy).add(lowerLimit);

    BigInteger gbModp = g.modPow(b, p);

    BigInteger[] b_gbModP = new BigInteger[2];
    b_gbModP[0] = b;
    b_gbModP[1] = gbModp;

    return b_gbModP;
  }

  // compute shared key k
  private static String getSharedKey(BigInteger gaModp, BigInteger b, BigInteger p) throws Exception {
    System.out.println("Computing shared key K...");
    String sharedKey;

    BigInteger gabModp = gaModp.modPow(b, p);

    sharedKey = gabModp.toString();
    System.out.println("Shared key K: " + sharedKey + "\n");

    return sharedKey;
  }
  
  // send back E(H(PW), gb mod p) to server
  private static void sendSecondReponse(DatagramSocket socket, InetAddress inet, int PORT_NUMBER, String passwordHash, BigInteger gbModp) throws Exception {
    try {
        // concatenate the values
        String concatenatedValues = passwordHash + "," + gbModp.toString();

        // array of bytes to store encrypted data to be sent
        byte[] encryptedMessage = encryptMessage(concatenatedValues, passwordHash);

        // send message
        DatagramPacket sendPacket = new DatagramPacket(encryptedMessage, encryptedMessage.length, inet, PORT_NUMBER);
        socket.send(sendPacket);
        System.out.println("Sending E(H(PW), gb mod p) to Host(Alice)\n");
    } catch (Exception e) {
        e.printStackTrace();
    }
  }

  // second response from server - E(K, Nonce_A)
  private static String[] awaitSecondResponse(DatagramSocket socket, String passwordHash) throws Exception {
    // Array of bytes to store data received in a packet
    byte[] receiveData = new byte[1024];

    // DatagramPacket to receive data
    DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);

    // receive data
    socket.receive(receivePacket);
    System.out.println("Receiving E(K, Nonce_A) from Host(Alice)\n");

    // decrypt received data
    byte[] decryptedMessageBytes = decryptMessage(receivePacket, passwordHash);

    // convert decrypted message in bytes to string value
    String decryptedMessage = new String(decryptedMessageBytes, StandardCharsets.UTF_8);

    // split up the values from the message
    String sharedKey = "";
    String nonce_a = "";

    int commaCount = 0; // using comma as a delimiter in my message
    for (int i = 0; i < decryptedMessage.length(); i++) {
        if (decryptedMessage.charAt(i) == ',') {
            commaCount += 1;
            continue;
        }                

        if (commaCount == 0) {
            sharedKey += decryptedMessage.charAt(i);
        }
        if (commaCount == 1) {
            nonce_a += decryptedMessage.charAt(i);
        }
    }

    // generate nonce b
    String nonce_b = "9";

    String[] sharedKey_nonceA_nonceB = new String[3];
    sharedKey_nonceA_nonceB[0] = sharedKey;
    sharedKey_nonceA_nonceB[1] = nonce_a;
    sharedKey_nonceA_nonceB[2] = nonce_b;

    return sharedKey_nonceA_nonceB;
  }

  // sends third response to server - E(K, Nonce_A + 1, Nonce_B)
  private static void sendThirdResponse(DatagramSocket socket, InetAddress inet, int PORT_NUMBER, String sharedKey, String nonce_a, String nonce_b, String passwordHash) throws Exception {
    try {
        // concatenate the values
        int nonce_a1 = Integer.parseInt(nonce_a) + 1;
        String concatenatedValues = sharedKey + "," + nonce_a1 + "," + nonce_b; 

        // array of bytes to store encrypted data to be sent
        byte[] encryptedMessage = encryptMessage(concatenatedValues, passwordHash);

        // send message
        DatagramPacket sendPacket = new DatagramPacket(encryptedMessage, encryptedMessage.length, inet, PORT_NUMBER);
        socket.send(sendPacket);
        System.out.println("Sending E(K, Nonce_A + 1, Nonce_B) to Host(Alice)\n");
    } catch (Exception e) {
        e.printStackTrace();
    }
  }

  // third response from server - E(K, nonce_b + 1)
  private static Boolean awaitThirdResponse(DatagramSocket socket, String passwordHash, String nonce_b) throws Exception {
    // Array of bytes to store data received in a packet
    byte[] receiveData = new byte[1024];

    // DatagramPacket to receive data
    DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);

    // receive data
    socket.receive(receivePacket);

    if (convert(receiveData).toString().equals("Login failed")) {
        System.out.println("Login failed. Terminating communication channel...");

        socket.close();

        return false;
    } else {
        System.out.println("Receiving E(K, nonce_b + 1) from Host(Alice)\n");
        // decrypt received data
        byte[] decryptedMessageBytes = decryptMessage(receivePacket, passwordHash);

        // convert decrypted message in bytes to string value
        String decryptedMessage = new String(decryptedMessageBytes, StandardCharsets.UTF_8);

        // split up the values from the message
        String nonce_b1 = "";

        int commaCount = 0; // using comma as a delimiter in my message
        for (int i = 0; i < decryptedMessage.length(); i++) {
            if (decryptedMessage.charAt(i) == ',') {
                commaCount += 1;
                continue;
            }
            if (commaCount == 1) {
                nonce_b1 += decryptedMessage.charAt(i);
            }
        }

        // check nonce_b + 1
        Boolean validNonce = checkNonce(nonce_b, nonce_b1);
        
        return validNonce;
    }
  }

  // check nonce_b + 1
  private static Boolean checkNonce(String nonce_b, String nonce_b1) {
    int nb = Integer.parseInt(nonce_b);
    int nb1 = Integer.parseInt(nonce_b1);

    if ((nb + 1) == nb1)
        return true;
    else
        return false;
    }


    // send message to host
    private static void sendMessage(DatagramSocket socket, InetAddress inet, int port, String msg, String sharedKey, String passwordHash) throws Exception {
        // concatenate values K||M||K
        String concatenated_K_M_K = sharedKey + "," + msg + "," + sharedKey;

        // compute hash = H(K||M||K)
        String hash = SHA1_Hash(concatenated_K_M_K);

        // concatenate values M||hash
        String concatenated_M_Hash = msg + "," + hash;

        // compute C = E(K, M||hash)
        byte[] ciphertext = encryptMessage(concatenated_M_Hash, sharedKey);

        // send C to Client(Bob)
        DatagramPacket sendPacket = new DatagramPacket(ciphertext, ciphertext.length, inet, port);
        socket.send(sendPacket);
        System.out.println("Sending Ciphertext to Host(Alice)\n");

        if (msg.equals("exit")) {
            System.out.println("Exiting communication channel...\n");
            socket.close(); // terminate socket
            SCANNER.close();
            System.exit(0);
        }
    }

    // receive message from host
    private static void receiveMessage(DatagramSocket socket, String sharedKey) throws Exception {
        // receive message
        // Array of bytes to store data received in a packet
        byte[] receiveData = new byte[1024];

        // DatagramPacket to receive data
        DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);

        // receive data
        socket.receive(receivePacket);

        // decrypt received data
        byte[] decryptedMessageBytes = decryptMessage(receivePacket, sharedKey);

        // convert decrypted message in bytes to string value
        String decryptedMessage = new String(decryptedMessageBytes, StandardCharsets.UTF_8);

        // get M||hash values
        // split up M and hash values
        String M = "";
        String hash = "";

        int commaCount = 0; // using comma as a delimiter in my message
        for (int i = 0; i < decryptedMessage.length(); i++) {
            if (decryptedMessage.charAt(i) == ',') {
                commaCount += 1;
                continue;
            
            }
            if (commaCount == 0) {
                M += decryptedMessage.charAt(i);
            }
            if (commaCount == 1) {
                hash += decryptedMessage.charAt(i);
            }
        }

        // concatenate K||M||K
        String concatenated_K_M_K = sharedKey + "," + M + "," + sharedKey;

        // compute hash_prime = H(K||M||K)
        String hash_prime = SHA1_Hash(concatenated_K_M_K);
        System.out.println("hash: " + hash);
        System.out.println("hash_prime: " + hash_prime);

        // check if hash == hash_prime
        if (hash.equals(hash_prime)) {
            System.out.println("Message authenticated.");
            // accept message
            System.out.println("Alice: " + M + "\n");
            if (M.equals("exit")) {
                System.out.println("Exiting communication channel...\n");
                socket.close(); // terminate socket
                SCANNER.close();
                System.exit(0);
            }
        } else {
            // reject message
            System.err.println("Message rejected. Terminating communication channel...\n");
            socket.close();
            SCANNER.close();
            System.exit(-1);
        }
    }
  
  // encryption function
  private static byte[] encryptMessage(String concatenatedValues, String encryptionKey) throws Exception {
    String updateKey = "";
    if (encryptionKey.length() > 128) {
        for (int i = 0; i < 128; i++) {
            updateKey += encryptionKey.charAt(i);
        }
    } else {
        updateKey = encryptionKey;
    }

    // initialise the key for RC4 encryption
    Key key = new SecretKeySpec(updateKey.getBytes(StandardCharsets.UTF_8), "RC4");

    // initialise cipher for encryption
    Cipher encryptCipher = Cipher.getInstance("RC4");
    encryptCipher.init(Cipher.ENCRYPT_MODE, key);

    // encrypt the message
    byte[] encryptedMessage = encryptCipher.doFinal(concatenatedValues.getBytes(StandardCharsets.UTF_8));

    return encryptedMessage;
  }

  // decryption function
  private static byte[] decryptMessage(DatagramPacket receivedPacket, String decryptionKey) throws Exception {
    String updateKey = "";
    if (decryptionKey.length() > 128) {
        for (int i = 0; i < 128; i++) {
            updateKey += decryptionKey.charAt(i);
        }
    } else {
        updateKey = decryptionKey;
    }

    // initialise the key for RC4 decryption
    Key key = new SecretKeySpec(updateKey.getBytes(StandardCharsets.UTF_8), "RC4");

    // initialise cipher for decryption
    Cipher decryptCipher = Cipher.getInstance("RC4");
    decryptCipher.init(Cipher.DECRYPT_MODE, key);

    // decrypt the received message
    byte[] decryptedMessage = decryptCipher.doFinal(receivedPacket.getData(), 0, receivedPacket.getLength());
    
    return decryptedMessage;
  }

  // utility method to convert byte array to string
  private static StringBuilder convert(byte[] a) {
    if (a == null) {
        return null;
    }

    StringBuilder sb = new StringBuilder();

    // flag
    int i = 0;
    while (a[i] != 0) {
        sb.append((char) a[i]);
        i++;
    }
    return sb;
}
}
