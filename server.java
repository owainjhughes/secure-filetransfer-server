
import java.io.DataInputStream;
import java.io.File;
import java.io.IOException;
import java.net.*;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Server 
{
    public static void main(String[] args) throws Exception
    {
        
        // SERVER   
        int port = Integer.parseInt(args[0]);
        try (ServerSocket socket = new ServerSocket(port)) {
            System.err.println("Waiting for a connection on port " + port);

            while (true)
            {
                Socket acceptedSocket = socket.accept();
                System.err.println("Accepted a connection from: " + acceptedSocket.getInetAddress());
                
                // GET DATA FROM CLIENT 
                DataInputStream in = new DataInputStream(acceptedSocket.getInputStream());
                try 
                {
                    // Read in data from client
                    byte[] encID = new byte[256];
                    in.readFully(encID);
                    byte[] encBytes = new byte[256];
                    in.readFully(encBytes);
                    byte[] signedBytes = new byte[256];
                    in.readFully(signedBytes);

                    // DECRYPTION
                    // Check the servers keys exist
                    if (!new File("server.pub").exists() || !new File("server.prv").exists())
                    {
                        System.out.println("Error: Servers keys do not exist");
                        return;
                    }
                    else
                    {
                        // Fetch own private key
                        File file = new File("server.prv");
                        byte[] prvBytes = Files.readAllBytes(file.toPath());
                        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(prvBytes);
                        KeyFactory kf = KeyFactory.getInstance("RSA");
                        PrivateKey prvKey = kf.generatePrivate(keySpec);

                        // Decrypt everything
                        Cipher decrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                        decrypt.init(Cipher.DECRYPT_MODE, prvKey);
                        byte[] decryptedID = decrypt.doFinal(encID);
                        byte[] decryptedBytes = decrypt.doFinal(encBytes);
                        String userID = new String(decryptedID);

                        // Verify signature
                        PublicKey pubKey = fetchUserKeys(userID);
                        Signature verified = Signature.getInstance("SHA1withRSA");
                        verified.initVerify(pubKey);
                        verified.update(encBytes);
                        Boolean verification = verified.verify(signedBytes);
                        if(verification == true)
                        {
                            System.out.println("Signature Verified");
                        }
                        else
                        {
                            System.out.println("Signature Verification Failed, Closing Connection");
                            acceptedSocket.close();
                        }

                        // Generate 16 random bytes and combine with clients bytes
                        SecureRandom rand = new SecureRandom();
                        byte[] newBytes = new byte[16];
                        rand.nextBytes(newBytes);
                        byte[] newKey = combineByteArrays(decryptedBytes, newBytes);

                        // Encrypt the new key
                        Cipher encrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                        encrypt.init(Cipher.ENCRYPT_MODE, pubKey);
                        byte[] encryptedNewBytes = encrypt.doFinal(newKey);

                        // Generate signature of new bytes
                        Signature signature = Signature.getInstance("SHA1withRSA");
                        signature.initSign(prvKey);
                        signature.update(encryptedNewBytes);
                        byte[] signedNewBytes = signature.sign();

                        // SEND DATA TO CLIENT
                        try 
                        {
                            acceptedSocket.getOutputStream().write(encryptedNewBytes);
                            acceptedSocket.getOutputStream().write(signedNewBytes);
                        }
                        catch (IOException e)
                        {
                            System.out.println("Error: Cannot connect to the client" + e);
                        }

                        //Generate AES Key
                        SecretKeySpec aesKey = new SecretKeySpec(newKey, "AES");
                        System.out.println("AES Key generated");
                        MessageDigest md = MessageDigest.getInstance("MD5");
                        byte[] initVector = md.digest(newKey);

                        // Begin Client communications
                        while(true)
                        {
                            System.out.println("Awaiting command from client...");
                            // Hypothetically size of byte here should be sent by client but since commands are always small 16 works every time here
                            byte[] encCommand = new byte[16];
                            in.readFully(encCommand);
                            String decCommand = decryptMessage(encCommand, aesKey, initVector);
                            initVector = md.digest(initVector);
                            System.err.println("Received Command: " + decCommand);
                            byte[] response = talkToClient(decCommand, aesKey, initVector);

                            // Get size of response so client knows how much data is expected
                            Integer noOfBytes = response.length;
                            byte [] responseSize = encryptInteger(noOfBytes, aesKey, initVector);
                            try 
                            {
                                acceptedSocket.getOutputStream().write(responseSize);
                                acceptedSocket.getOutputStream().write(response);
                                acceptedSocket.getOutputStream().flush();
                            }
                            catch (IOException e)
                            {
                                System.out.println("Error: Cannot connect to the client" + e);
                            }
                        }
                    }
                }
                catch (Exception e)
                {
                    System.out.println("Error: Cannot connect to the client" + e);
                }
            }
        }
    }
    public static PublicKey fetchUserKeys(String userid) throws Exception
    {
        File pub = new File(userid+".pub");
        byte[] pubBytes = Files.readAllBytes(pub.toPath());
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pubBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey pubKey = kf.generatePublic(keySpec);

        return pubKey;
    }

    // With help from https://www.baeldung.com/java-concatenate-byte-arrays
    public static byte[] combineByteArrays(byte[] a, byte[] b)
    {
        byte[] combined = new byte[a.length + b.length];
        System.arraycopy(a, 0, combined, 0, a.length);
        System.arraycopy(b, 0, combined, a.length, b.length);
        return combined;
    }

    public static String ListFiles() 
    {
        File[] files = new File("./").listFiles();
        String fileNames = "";
        for (File file : files)
        {
            if(file.isFile() && !file.getName().endsWith(".prv"))
            {
                fileNames = fileNames+(file.getName()+"\n");
            }
        }
        return fileNames;
    }

    public static List<String> getFiles() 
    {
        File[] files = new File("./").listFiles();
        List<String> fileNames = new ArrayList<String>();
        for (File file : files)
        {
            if(file.isFile() && !file.getName().endsWith(".prv"))
            {
                fileNames.add(file.getName());
            }
        }
        return fileNames;
    }

    public static byte[] encryptCommand(String command, SecretKeySpec aesKey, byte[] initVector) throws Exception
    {
        // Encrypt using AES key
        Cipher encrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        encrypt.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(initVector));
        byte[] encryptedCommand = encrypt.doFinal(command.getBytes());

        return encryptedCommand;
    }

    public static byte[] encryptInteger(Integer byteSize, SecretKeySpec aesKey, byte[] initVector) throws Exception
    {
        Cipher encrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        encrypt.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(initVector));
        byte[] encryptedCommand = encrypt.doFinal(byteSize.toString().getBytes());

        return encryptedCommand;
    }

    public static byte[] encryptFile(File file, SecretKeySpec aesKey, byte[] initVector) throws Exception
    {
        Cipher encrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        encrypt.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(initVector));
        byte[] encryptedCommand = encrypt.doFinal(Files.readAllBytes(file.toPath()));

        return encryptedCommand;
    }

    public static String decryptMessage(byte[] message, SecretKeySpec aesKey, byte[] initVector) throws Exception
    {
        Cipher decrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        decrypt.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(initVector));
        byte[] decryptedMessage = decrypt.doFinal(message);
        
        return new String(decryptedMessage);
    }

    public static byte[] talkToClient(String decCommand, SecretKeySpec aeskey, byte[] initVector) throws Exception
    {
        if (decCommand.equals("ls"))
        {
            System.out.println("Fetching files...");
            String files = ListFiles();

            byte[] encFiles = encryptCommand(files, aeskey, initVector);
            return encFiles;
        }
        else if(decCommand.startsWith("get"))
        {
            // With help from https://stackoverflow.com/questions/5067942/what-is-the-best-way-to-extract-the-first-word-from-a-string-in-java regarding getting first string in command
            String commandStrings[] = decCommand.split(" ", 2);
            String commandData = commandStrings[1];
            List<String> files = getFiles();
            if (files.contains(commandData))
            {
                File file = new File("./"+commandData);
                byte[] fileToSend = encryptFile(file, aeskey, initVector);
                System.out.println(commandData+" sent to client");
                return fileToSend;
            }
            String errorResponse = "No such file exists";
            System.err.println("Error fetching file: No such file exists");
            byte[] errorResponseAsBytes = encryptCommand(errorResponse, aeskey, initVector);
            return errorResponseAsBytes;
        }
        else
        {
            System.out.println("Unknown Command");
            byte[] bytes = new byte[256];
            return bytes;
        }
    }
}
