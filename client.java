import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Client 
{
    public static void main(String[] args) throws Exception
    {
        if (args.length < 3)
        {
            System.out.println("Usage: java client <host> <port> <userID>");
            return;
        }

        // Client Parameters
        String host = args[0];
        int port = Integer.parseInt(args[1]);
        String userID = args[2];

        // Client Variables
        byte[] bytes;
        byte[] encryptedID;
        byte[] encryptedBytes;
        byte[] signedBytes;

        // Check the users keys exist
        if (!new File("server.pub").exists() || !new File(userID+".prv").exists() || !new File(userID+".pub").exists())
        {
            System.out.println("Error: User or Server Public keys do not exist");
            return;
        }
        else
        {

            // 16 random bytes
            SecureRandom rand = new SecureRandom();
            bytes = new byte[16];
            rand.nextBytes(bytes);

            // Fetch public key of server for encryption
            File pub = new File("server.pub");
            byte[] pubBytes = Files.readAllBytes(pub.toPath());
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pubBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey pubKey = kf.generatePublic(keySpec);

            // Fetch private key of user for signature
            File prv = new File(userID+".prv");
            byte[] prvBytes = Files.readAllBytes(prv.toPath());
            PKCS8EncodedKeySpec prvSpec = new PKCS8EncodedKeySpec(prvBytes);
            KeyFactory kf2 = KeyFactory.getInstance("RSA");
            PrivateKey prvKey = kf2.generatePrivate(prvSpec);
            
            // Encrypt users ID and the 16 bytes
            Cipher encrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            encrypt.init(Cipher.ENCRYPT_MODE, pubKey);
            encryptedID = encrypt.doFinal(userID.getBytes());
            encryptedBytes = encrypt.doFinal(bytes);
        
            // Generate signature of the bytes
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initSign(prvKey);
            signature.update(encryptedBytes);
            signedBytes = signature.sign();
        }

        // SEND DATA TO SERVER
        try 
        {
            try (Socket socket = new Socket(host, port)) 
            {
                System.out.println("Connected to: " + host);
                System.out.println("On Port: " + port);
                System.out.println("As User: " + userID);
                
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                out.write(encryptedID);
                out.write(encryptedBytes);
                out.write(signedBytes);
                out.flush();

                // RECEIVE DATA FROM SERVER
                DataInputStream in = new DataInputStream(socket.getInputStream());
                byte[] encryptedKey = new byte[256];
                in.read(encryptedKey);
                byte[] signedNewBytes = new byte[256];
                in.read(signedNewBytes);

                // Fetch private key of user for decryption
                File prv = new File(userID+".prv");
                byte[] prvBytes = Files.readAllBytes(prv.toPath());
                PKCS8EncodedKeySpec prvSpec = new PKCS8EncodedKeySpec(prvBytes);
                KeyFactory kf2 = KeyFactory.getInstance("RSA");
                PrivateKey prvKey = kf2.generatePrivate(prvSpec);

                // Decrypt the new key
                Cipher decrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                decrypt.init(Cipher.DECRYPT_MODE, prvKey);
                byte[] decryptedKey = decrypt.doFinal(encryptedKey);

                // Verify signature of the new key
                PublicKey pubKey = fetchUserKeys("server");
                Signature verified = Signature.getInstance("SHA1withRSA");
                verified.initVerify(pubKey);
                verified.update(encryptedKey);
                Boolean verification = verified.verify(signedNewBytes);

                // Check signature verification AND first 16 bytes are same
                if (verification == true && Arrays.equals(Arrays.copyOfRange(decryptedKey, 0, 16), bytes))
                {
                    System.out.println("Signature verified and Key generated Successfully");
                }
                else
                {
                    System.out.println("Signature verification Failed, Closing Connection");
                    socket.close();
                }
                // Generate hash of bytes for initilisation vector
                MessageDigest md = MessageDigest.getInstance("MD5");
                byte[] initVector = md.digest(decryptedKey);

                //Generate AES Key and begin server communications
                SecretKeySpec aesKey = new SecretKeySpec(decryptedKey, "AES");

                Boolean commandTaken = false;
                Boolean dataToDecrypt = false;
                Boolean fileToDecrypt = false;
                while (!commandTaken)
                {
                    System.out.println("What would you like the server to do?");
                    BufferedReader command = new BufferedReader(new InputStreamReader(System.in));
                    String input = command.readLine();
                    String[] commands = input.split(" ");
                    if (input.equals("ls"))
                    {
                        System.out.println("Sending Command: " + input);
                        byte[] encryptedCommand = encryptCommand(input, aesKey, initVector);
                        initVector = md.digest(initVector);
                        out.write(encryptedCommand);
                        dataToDecrypt = true;
                        commandTaken = true;
                    }
                    else if (input.startsWith("get") && commands.length==2)
                    {
                        System.err.println("Attempting to fetch file: "+commands[1]);
                        byte[] encryptedCommand = encryptCommand(input, aesKey, initVector);
                        initVector = md.digest(initVector);
                        out.write(encryptedCommand);
                        fileToDecrypt = true;
                        commandTaken = true;
                    }
                    else if (input.equals("bye"))
                    {
                        System.out.println("Goodbye");
                        socket.close();
                        System.exit(0);
                    }
                    else
                    {
                        System.out.println("Invalid Command: Usage: ls, get <filename>, bye");
                    }
                    if (dataToDecrypt)
                    {
                        // Get number of bytes so it knows how much data is being sent
                        byte[] encSize = new byte[16];
                        in.readFully(encSize);
                        Integer byteSize = decryptSize(encSize, aesKey, initVector);

                        // Then decrypt the actual data
                        byte[] encryptedData = new byte[byteSize];
                        in.readFully(encryptedData);
                        String message = decryptMessage(encryptedData, aesKey, initVector);
                        System.out.println(message);
                        dataToDecrypt = false;
                        commandTaken = false;
                    }
                    else if (fileToDecrypt)
                    {
                        // Get number of bytes so it knows how much data is being sent
                        byte[] encSize = new byte[16];
                        in.readFully(encSize);
                        Integer byteSize = decryptSize(encSize, aesKey, initVector);

                        // Then decrypt the actual data
                        byte[] encryptedData = new byte[byteSize];
                        in.readFully(encryptedData);
                        String message = decryptFile(encryptedData, commands[1], aesKey, initVector);
                        System.out.println(message);
                        fileToDecrypt = false;
                        commandTaken = false;
                    }
                }
            }
        }
        catch (IOException error)
        {
            System.out.println("Error: Cannot connect to the server" + error);
        }
    }
    public static PublicKey fetchUserKeys(String userID) throws Exception
    {
        File pub = new File(userID+".pub");
        byte[] pubBytes = Files.readAllBytes(pub.toPath());
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pubBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey pubKey = kf.generatePublic(keySpec);

        return pubKey;
    }
    
    // With help from https://stackoverflow.com/questions/17322002/what-causes-the-error-java-security-invalidkeyexception-parameters-missing regarding adding the Initilization vector 
    public static byte[] encryptCommand(String command, SecretKeySpec aesKey, byte[] initVector) throws Exception
    {
        Cipher encrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        encrypt.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(initVector));
        byte[] encryptedCommand = encrypt.doFinal(command.getBytes());

        return encryptedCommand;
    }
    public static String decryptMessage(byte[] message, SecretKeySpec aesKey, byte[] initVector) throws Exception
    {
        Cipher decrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        decrypt.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(initVector));
        byte[] decryptedMessage = decrypt.doFinal(message);

        return new String(decryptedMessage);
    }
    public static Integer decryptSize(byte[] message, SecretKeySpec aesKey, byte[] initVector) throws Exception
    {
        Cipher decrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        decrypt.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(initVector));
        byte[] decryptedMessage = decrypt.doFinal(message);
        String size =  new String(decryptedMessage);
        
        return Integer.parseInt(size);
    }
    public static String decryptFile(byte[] message, String fileName, SecretKeySpec aesKey, byte[] initVector) throws Exception
    {
        Cipher decrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        decrypt.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(initVector));
        byte[] decryptedMessage = decrypt.doFinal(message);

        // Not the best way to handle incorrect files but it works
        String errMessage = new String(decryptedMessage);
        if (errMessage.equals("No such file exists"))
        {
            return errMessage;
        }
        else
        {
            // Can be tested to see if it works by changing the FileOutputStream parameters e.g. ("CopyOf+fileName)
            try (FileOutputStream fos = new FileOutputStream("CopyOf"+fileName)) 
            {
                fos.write(decryptedMessage);
            }
            return fileName+" has been fetched";
        }
    }
}
