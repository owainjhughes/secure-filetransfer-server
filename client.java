import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;

public class client 
{
    public static void main(String[] args) throws Exception
    {
        if (args.length < 3)
        {
            System.out.println("Usage: java client <host> <port> <userid>");
            return;
        }

        // Client Parameters
        String host = args[0];
        int port = Integer.parseInt(args[1]);
        String userid = args[2];

        // Client Variables
        byte[] bytes;
        byte[] encryptedID;
        byte[] encryptedBytes;
        byte[] signedBytes;

        // Check the users keys exist
        if (!new File("server.pub").exists() || !new File("server.prv").exists() || !new File(userid+".prv").exists() || !new File(userid+".pub").exists())
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
            System.out.println("Random Unencrypted Bytes: " + Arrays.toString(bytes));

            // Fetch public key of server for encryption
            File pub = new File("server.pub");
            byte[] pubBytes = Files.readAllBytes(pub.toPath());
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pubBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey pubKey = kf.generatePublic(keySpec);

            // Fetch private key of user for signature
            File prv = new File(userid+".prv");
            byte[] prvBytes = Files.readAllBytes(prv.toPath());
            PKCS8EncodedKeySpec prvSpec = new PKCS8EncodedKeySpec(prvBytes);
            KeyFactory kf2 = KeyFactory.getInstance("RSA");
            PrivateKey prvKey = kf2.generatePrivate(prvSpec);
            
            // Encrypt userid and bytes
            Cipher encrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            encrypt.init(Cipher.ENCRYPT_MODE, pubKey);
            encryptedID = encrypt.doFinal(userid.getBytes());
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
            try (Socket socket = new Socket(host, port)) {
                System.out.println("Connected to: " + host);
                System.out.println("Port: " + port);
                System.out.println("User: " + userid);
                System.out.println("Bytes:" + new String(bytes));
                //System.out.println("Sending Encrypted:\n User:"+Arrays.toString(encryptedID));
                //System.out.println("Bytes: "+ Arrays.toString(encryptedBytes));
                //System.out.println("Signed: "+Arrays.toString(signedBytes));
                
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                out.write(encryptedID);
                out.write(encryptedBytes);
                out.write(signedBytes);
            }
        }
        catch (IOException e)
        {
            System.out.println("Error: Cannot connect to the server" + e);
        }
    }
}
