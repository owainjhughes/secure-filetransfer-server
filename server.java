
import java.io.DataInputStream;
import java.io.File;
import java.net.*;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;

public class server 
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
                    // Read in data and print for debugging
                    byte[] encID = new byte[256];
                    in.readFully(encID);
                    byte[] encBytes = new byte[256];
                    in.readFully(encBytes);
                    byte[] signedBytes = new byte[256];
                    in.readFully(signedBytes);
                    // These were mainly for debugging
                    //System.out.println("Client: \n Encrypted ID:"+Arrays.toString(encID));
                    //System.out.println("Encypted Bytes: "+ Arrays.toString(encBytes));
                    //System.out.println("Signed Bytes: "+Arrays.toString(signedBytes));

                    // DECRYPTION
                    // Check the users keys exist
                    if (!new File("server.pub").exists() || !new File("server.prv").exists())
                    {
                        System.out.println("Error: User keys do not exist");
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
                        String bytes = new String(decryptedBytes);

                        // Verify signature
                        PublicKey pubKey = fetchUserKeys(userID);
                        Signature verified = Signature.getInstance("SHA1withRSA");
                        verified.initVerify(pubKey);
                        verified.update(encBytes);
                        Boolean verification = verified.verify(signedBytes);

                        System.out.println("Decrypted ID: " + userID);
                        System.out.println("Decrypted Bytes: " + bytes);
                        System.out.println("Signature Verified: " + verification);
                    }
                }
                catch (Exception e)
                {
                    System.out.println("Error: Cannot connect to the server" + e);
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
}
