import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
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

        //connection params
        String host = args[0];
        int port = Integer.parseInt(args[1]);
        String userid = args[2];

        //16 random bytes
        SecureRandom rand = new SecureRandom();
        byte[] bytes = new byte[16];
        rand.nextBytes(bytes);
        System.out.println("Random Unencrypted Bytes: " + bytes);

        byte[] encryptedID = null;
        byte[] encryptedBytes = null;

        //check the users keys exist
        if (!new File("server.pub").exists() || !new File("server.prv").exists())
        {
            System.out.println("Error: User or Server keys do not exist");
            return;
        }
        else
        {
            //fetch public key
            File pub = new File("server.pub");
            byte[] pubBytes = Files.readAllBytes(pub.toPath());
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pubBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey pubKey = kf.generatePublic(keySpec);

            //encrypt userid and bytes
            Cipher encrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            encrypt.init(Cipher.ENCRYPT_MODE, pubKey);
            encryptedID = encrypt.doFinal(userid.getBytes());
            encryptedBytes = encrypt.doFinal(bytes);
        }



        try 
        {
            //open connection and send data
            Socket socket = new Socket(host, port);
            System.out.println("Connected to: " + host + "\n Port: " + port + "\n User:" + userid + "\n Bytes:" + new String(bytes));
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            System.out.println("Sending Encrypted:\n User:"+encryptedID + "\n Bytes: "+ encryptedBytes);
            out.write(encryptedID);
            out.write(encryptedBytes);
            socket.close();
        }
        catch (Exception e)
        {
            System.out.println("Error: Cannot connect to the server" + e);
        }
    }
}
