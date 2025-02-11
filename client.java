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
        if (!new File("server.pub").exists() || !new File("server.prv").exists() || !new File(userID+".prv").exists() || !new File(userID+".pub").exists())
        {
            System.out.println("Error: User or Server keys do not exist");
            return;
        }
        else
        {

            // 16 random bytes
            SecureRandom rand = new SecureRandom();
            bytes = new byte[16];
            rand.nextBytes(bytes);
            //System.out.println("Random Unencrypted Bytes: " + Arrays.toString(bytes));

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
            
            // Encrypt userID and bytes
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
                //System.out.println("Bytes:" + new String(bytes));
                //System.out.println("Sending Encrypted:\n User:"+Arrays.toString(encryptedID));
                //System.out.println("Bytes: "+ Arrays.toString(encryptedBytes));
                //System.out.println("Signed: "+Arrays.toString(signedBytes));
                
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
                //System.out.println("Decrypted Key: " + Arrays.toString(decryptedKey));

                // Verify signature of the new key
                PublicKey pubKey = fetchUserKeys("server");
                Signature verified = Signature.getInstance("SHA1withRSA");
                verified.initVerify(pubKey);
                verified.update(encryptedKey);
                Boolean verification = verified.verify(signedNewBytes);
                // Check signature verification AND first 16 bytes are same
                if (verification == true || Arrays.equals(Arrays.copyOfRange(decryptedKey, 0, 16), bytes))
                {
                    System.out.println("Signature Verified");
                }
                else
                {
                    System.out.println("Signature Verification Failed, Closing Connection");
                    socket.close();
                }

                //Generate AES Key and begin server communications
                SecretKeySpec aesKey = new SecretKeySpec(decryptedKey, "AES");
                //System.err.println(aesKey.toString());

                BufferedReader command = new BufferedReader(new InputStreamReader(System.in));
                String input = command.readLine();
                if (input.equals("ls"))
                {
                    System.err.println("Sending Command: " + input);
                    //byte[] encFiles = new byte[256];
                    byte[] encryptedCommand = encryptCommand(input, aesKey);
                    //System.err.println("Sending Encrypted Command: " + Arrays.toString(encryptedCommand));
                    //String decCommand = decryptMessage(encryptedCommand, aesKey);
                    //System.err.println("Decrypted Command: " + decCommand);
                    //out.writeUTF(input);
                    out.write(encryptedCommand);
                    //System.err.println("Sent Encrypted Command");
                    //in.read(encFiles);
                    //String files = decryptMessage(encFiles, aesKey);
                    //System.out.println(files);
                }
                else if (input.startsWith("get"))
                {
        
                }
                else if (input.equals("bye"))
                {
                    System.out.println("Goodbye");
                    socket.close();
                }
                else
                {
                    System.out.println("Invalid Command: Usage: ls, get <filename>, bye");
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
    public static byte[] encryptCommand(String command, SecretKeySpec aesKey) throws Exception
    {
        // Encrypt using AES key
        Cipher encrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        encrypt.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(new byte[16]));
        byte[] encryptedCommand = encrypt.doFinal(command.getBytes());
        return encryptedCommand;
    }
    public static String decryptMessage(byte[] message, SecretKeySpec aesKey) throws Exception
    {
        // Decrypt using AES key
        Cipher decrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        decrypt.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(new byte[16]));
        byte[] decryptedMessage = decrypt.doFinal(message);
        return new String(decryptedMessage);
    }
}
