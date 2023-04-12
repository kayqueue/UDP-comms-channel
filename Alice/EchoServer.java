import java.io.File;
import java.io.FileNotFoundException;
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

public class EchoServer {

    // Port number for the socket
    private static final int PORT_NUMBER = 1234;

    private static final Scanner SCANNER = new Scanner(System.in);

    public static void main(String[] args) throws Exception {
        String[] params = readFile("dhparams.txt");
        BigInteger p = new BigInteger(params[0]);
        BigInteger g = new BigInteger(params[1]);
        String passwordHash = params[2];

        Boolean connectionEstablished = false;

        try {
            // Create a new DatagramSocket to receive and send packets
            DatagramSocket socket = new DatagramSocket(PORT_NUMBER);
            socket.setSoTimeout(30 * 1000); // socket closes after 30 seconds of silence
            System.out.println("Host is running and listening on port " + PORT_NUMBER + "...\n");

            /* Attemp to establish connection */
            // Array of bytes to store data received in a packet
            byte[] receiveData = new byte[1024];

            // DatagramPacket to receive data
            DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
            socket.receive(receivePacket);
            String receiveMessage = new String(receivePacket.getData());
            System.out.println("Client: " + receiveMessage);

            // Get the address and port of the sender
            InetAddress inet = receivePacket.getAddress();
            int senderPort = receivePacket.getPort();
            String sharedKey = "";

            // client sends a connection request
            if (convert(receiveData).toString().equals("Bob")) {
                // process connection request and send E(H(PW), p, g, ga mod p) to client
                BigInteger[] a_gaModp = connectionRequest(passwordHash, p, g, socket, inet, senderPort);
                BigInteger a = a_gaModp[0];
                
                // await and process response from client - E(H(PW), gb mod p)
                BigInteger gbModp = awaitSecondResponse(passwordHash, socket, inet, senderPort, SCANNER);

                // compute shared key k
                sharedKey = getSharedKey(gbModp, a, p);
                // System.out.println("sharedKey: " + sharedKey);

                // sends second response to client - E(K, Nonce_a)
                int nonce_a = sendSecondResponse(socket, inet, senderPort, sharedKey, passwordHash);

                // await and process third response from client - E(K, nonce_a + 1, nonce_b) and sends back E(K, nonce_b + 1) back to client
                Boolean validNonce = awaitThirdResponse(passwordHash, socket, inet, senderPort, String.valueOf(nonce_a));

                // default deny
                if (validNonce) {
                    connectionEstablished = true;
                    System.out.println("Connection established!\n");
                } else {
                    socket.close(); // terminate connection
                }

            }

            if (connectionEstablished) {
                // Receive data and print it to the console
                while (true) {
                    receiveMessage(socket, sharedKey);

                    System.out.print("Your message: ");
                    String message = SCANNER.nextLine();

                    sendMessage(socket, inet, senderPort, message, sharedKey, passwordHash);
                    
                    
                    // // Array of bytes to store data received in a packet
                    // receiveData = new byte[1024];
            
                    // // DatagramPacket to receive data
                    // receivePacket = new DatagramPacket(receiveData, receiveData.length);

                    // // Receive data and print it to the console
                    // socket.receive(receivePacket);
                    // receiveMessage = new String(receivePacket.getData());
                    // System.out.println("Bob: " + receiveMessage);

                    // System.out.print("Your message: ");
                    // String message = SCANNER.nextLine();

                    // // Array of bytes to store data to be sent
                    // byte[] sendData = message.getBytes(StandardCharsets.UTF_8);

                    // // DatagramPacket to send data
                    // DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, inet, PORT_NUMBER);

                    // Send the data
                    // socket.send(sendPacket);
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

    // read DH parameters and hashed password from file
    private static String[] readFile(String filename) {
        String[] params = new String[3];
        try {
            // read file
            File file = new File(filename);
            Scanner scanner = new Scanner(file);

            // flag
            int i = 0;
            while (scanner.hasNextLine()) {
                String data = scanner.nextLine();
                params[i] = data;
                i++;
            }
            scanner.close();

            return params;
        } catch (FileNotFoundException e) {
            System.out.println("File not found.");
            e.printStackTrace();
        }
        return params;
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

    // receive connection request from client
    private static BigInteger[] connectionRequest(String passwordHash, BigInteger p, BigInteger g, DatagramSocket socket, InetAddress inet, int senderPort) throws Exception {
        System.out.println("Connection request received...");

        // generate gaModp value and sends E(H(PW), p, g, ga mod p) to Client(Bob)
        BigInteger[] a_gaModp = generateLog(p, g);
        BigInteger gaModp = a_gaModp[1];

        // concatenate the values
        String concatenatedValues = passwordHash + "," + p.toString() + "," + g.toString() + "," + gaModp.toString();
        System.out.println("Sending E(H(PW), p, g, ga mod p) to Client(Bob)\n");

        // array of bytes to store encrypted data to be sent
        byte[] encryptedMessage = encryptMessage(concatenatedValues, passwordHash);

        // send message
        DatagramPacket sendPacket = new DatagramPacket(encryptedMessage, encryptedMessage.length, inet, senderPort);
        socket.send(sendPacket);

        return a_gaModp;
    }

    // generate random 'a' value and compute ga mod p
    private static BigInteger[] generateLog(BigInteger p, BigInteger g) {
        // p = upper limit, 1 = lower limit
        BigInteger lowerLimit = new BigInteger("1");
        BigInteger dummy = p.subtract(lowerLimit);
        Random rand = new Random();
        int len = p.bitLength();
        BigInteger a = new BigInteger(len, rand);

        if (a.compareTo(lowerLimit) < 0)
            a = a.add(lowerLimit);
        if (a.compareTo(dummy) >= 0)
            a = a.mod(dummy).add(lowerLimit);

        BigInteger gaModp = g.modPow(a, p);

        BigInteger[] a_gaModp = new BigInteger[2];
        a_gaModp[0] = a;
        a_gaModp[1] = gaModp;

        return a_gaModp;
    }

    // second response/request from client - E(H(PW), gb mod p)
    private static BigInteger awaitSecondResponse(String passwordHash, DatagramSocket socket, InetAddress inet, int senderPort, Scanner SCANNER) throws Exception {
        // Array of bytes to store data received in a packet
        byte[] receiveData = new byte[1024];

        // DatagramPacket to receive data
        DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);

        // receive data
        socket.receive(receivePacket);
        System.out.println("Receiving E(H(PW), gb mod p) from Client(Bob)\n");

        // decrypt received data
        byte[] decryptedMessageBytes = decryptMessage(receivePacket, passwordHash);

        // convert decrypted message in bytes to string value
        String decryptedMessage = new String(decryptedMessageBytes, StandardCharsets.UTF_8);

        // split up the values from the message
        String pwHash = "";
        String gbModpString = "";

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
                gbModpString += decryptedMessage.charAt(i);
            }
        }

        if (!passwordHash.equals(pwHash)) {
            socket.close();
            SCANNER.close();
            System.err.println("Wrong password from Client. Terminating communication channel...\n");
            System.exit(-1);
        }

        BigInteger gbModp = new BigInteger(gbModpString);

        return gbModp;
    }

    // compute shared key k
    private static String getSharedKey(BigInteger gbModp, BigInteger a, BigInteger p) throws Exception {
        System.out.println("Computing shared key K...");
        String sharedKey;

        BigInteger gabModp = gbModp.modPow(a, p);

        sharedKey = gabModp.toString();
        System.out.println("Shared key K: " + sharedKey + "\n");

        return sharedKey;
    }

    // sends back E(K, Nonce_a) back to client
    private static int sendSecondResponse(DatagramSocket socket, InetAddress inet, int senderPort, String sharedKey, String passwordHash) throws Exception {
        // generate nonce_a
        int nonce_a = 0;

        // concatenate the values
        String concatenatedValues = sharedKey + "," + String.valueOf(nonce_a);

        // array of bytes to store encrypted data to be sent
        byte[] encryptedMessage = encryptMessage(concatenatedValues, passwordHash);

        // send message
        DatagramPacket sendPacket = new DatagramPacket(encryptedMessage, encryptedMessage.length, inet, senderPort);
        socket.send(sendPacket);
        System.out.println("Sending E(K, nonce_a) to Client(Bob)\n");

        return nonce_a;
    }

    // third response/request from client - E(K, NonceA + 1, NonceB)
    private static Boolean awaitThirdResponse(String passwordHash, DatagramSocket socket, InetAddress inet, int senderPort, String nonce_a) throws Exception {
        System.out.println("E(K, NonceA + 1, NonceB) received");
        // Array of bytes to store data received in a packet
        byte[] receiveData = new byte[1024];

        // DatagramPacket to receive data
        DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);

        // receive data
        socket.receive(receivePacket);
        System.out.println("Receiving E(K, nonce_a + 1, nonce_b) from Client(Bob)\n");

        // decrypt received data
        byte[] decryptedMessageBytes = decryptMessage(receivePacket, passwordHash);

        // convert decrypted message in bytes to string value
        String decryptedMessage = new String(decryptedMessageBytes, StandardCharsets.UTF_8);


        // split up the values from the message
        String sharedKey = "";
        String nonce_a1 = "";
        String nonce_b = "";

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
                nonce_a1 += decryptedMessage.charAt(i);
            }
            if (commaCount == 2) {
                nonce_b += decryptedMessage.charAt(i);
            }
        }

        Boolean validNonce = checkNonce(nonce_a, nonce_a1);

        if (validNonce)
            sendThirdResponse(validNonce, socket, inet, senderPort, sharedKey, passwordHash, nonce_b);

        return validNonce;
    }

    // check nonce_a + 1
    private static Boolean checkNonce(String nonce_a, String nonce_a1) {
        int na = Integer.parseInt(nonce_a);
        int na1 = Integer.parseInt(nonce_a1);

        if ((na + 1) == na1)
            return true;
        else
            return false;
    }
    
    // send third response to client - E(K, nonce_b + 1)
    private static void sendThirdResponse(Boolean validNonce, DatagramSocket socket, InetAddress inet, int senderPort, String sharedKey, String passwordHash, String nonce_b) throws Exception {
        if (!validNonce) {
            String msg = "Login Failed";
            byte[] msgBytes = msg.getBytes(StandardCharsets.UTF_8);
            DatagramPacket loginFailed = new DatagramPacket(msgBytes, msgBytes.length, inet, senderPort);
            socket.send(loginFailed);
        } else {
            // get nonce_b + 1
            int nonce_b1 = Integer.parseInt(nonce_b) + 1;

            // concatenate the values
            String concatenatedValues = sharedKey + "," + String.valueOf(nonce_b1);

            // array of bytes to store encrypted data to be sent
            byte[] encryptedMessage = encryptMessage(concatenatedValues, passwordHash);

            // send message
            DatagramPacket sendPacket = new DatagramPacket(encryptedMessage, encryptedMessage.length, inet, senderPort);
            socket.send(sendPacket);
            System.out.println("Login successful, sending E(K, nonce_b + 1) back to Client(Bob)\n");
        }
    }

    // send message to Client
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
        System.out.println("Sending Ciphertext to Client(Bob)\n");

        if (msg.equals("exit")) {
            System.out.println("Exiting communication channel...\n");
            socket.close(); // terminate socket
            SCANNER.close();
            System.exit(0);
        }
    }

    // receive message from Client
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
            System.out.println("Bob: " + M + "\n");
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
}
