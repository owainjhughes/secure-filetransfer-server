
import java.io.DataInputStream;
import java.io.File;
import java.net.*;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.Cipher;

public class server 
{
    public static void main(String[] args) throws Exception
    {
        
        //open server and port
        int port = Integer.parseInt(args[0]);
        ServerSocket socket = new ServerSocket(port);
        System.err.println("Waiting for a connection on port " + port);
        Socket acceptedSocket = socket.accept();
        //read data
        DataInputStream in = new DataInputStream(acceptedSocket.getInputStream());
        try 
        {
            //String x = in.readUTF();
            byte[] encID = new byte[256];
            in.readFully(encID);
            byte[] encBytes = in.readAllBytes();
            System.out.println("Client: \n Encrypted ID:"+encID + "\n Encypted Bytes: "+ encBytes);

            //decrypt(encID, encBytes);
            if (!new File("server.pub").exists() || !new File("server.prv").exists())
            {
                System.out.println("Error: User keys do not exist");
                return;
            }
            else
            {
                //fetch private key
                File file = new File("server.prv");
                byte[] prvBytes = Files.readAllBytes(file.toPath());
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(prvBytes);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                PrivateKey prvKey = kf.generatePrivate(keySpec);
                
                //decrypt everything
                Cipher decrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                decrypt.init(Cipher.DECRYPT_MODE, prvKey);
                byte[] decryptedID = decrypt.doFinal(encID);
                byte[] decryptedBytes = decrypt.doFinal(encBytes);
                
                System.out.println("Decrypted ID: " + new String(decryptedID));
                System.out.println("Decrypted Bytes: " + new String(decryptedBytes));
                socket.close();
            }
        }
        catch (Exception e)
        {
            System.out.println("Error: Cannot connect to the server" + e);
        }
        System.err.println("Accepted a connection from: " + acceptedSocket.getInetAddress());
    }
}
