import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
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

public class ClientGUI extends JFrame {
    private JTextField hostField;
    private JTextField portField;
    private JTextField userField;
    private JTextArea outputArea;
    private JButton connectButton;
    private JButton lsButton;
    private JButton getButton;
    private JButton disconnectButton;

    // Connection variables
    private Socket socket;
    private DataOutputStream out;
    private DataInputStream in;
    private SecretKeySpec aesKey;
    private byte[] initVector;
    private MessageDigest md;
    private boolean connected = false;

    public ClientGUI() {
        initializeGUI();
    }

    private void initializeGUI() {
        setTitle("Secure File Transfer Client");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new BorderLayout());

        // Connection panel
        JPanel connectionPanel = createConnectionPanel();
        add(connectionPanel, BorderLayout.NORTH);

        // Output area
        outputArea = new JTextArea(15, 50);
        outputArea.setEditable(false);
        outputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane scrollPane = new JScrollPane(outputArea);
        scrollPane.setBorder(BorderFactory.createTitledBorder("Server Output"));
        add(scrollPane, BorderLayout.CENTER);

        // Command panel
        JPanel commandPanel = createCommandPanel();
        add(commandPanel, BorderLayout.SOUTH);

        pack();
        setLocationRelativeTo(null);
        updateButtonStates();
    }

    private JPanel createConnectionPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));
        GridBagConstraints gbc = new GridBagConstraints();

        gbc.insets = new Insets(5, 5, 5, 5);

        // Host
        gbc.gridx = 0;
        gbc.gridy = 0;
        panel.add(new JLabel("Host:"), gbc);
        gbc.gridx = 1;
        hostField = new JTextField("localhost", 10);
        panel.add(hostField, gbc);

        // Port
        gbc.gridx = 2;
        gbc.gridy = 0;
        panel.add(new JLabel("Port:"), gbc);
        gbc.gridx = 3;
        portField = new JTextField("8080", 10);
        panel.add(portField, gbc);

        // User
        gbc.gridx = 4;
        gbc.gridy = 0;
        panel.add(new JLabel("User:"), gbc);
        gbc.gridx = 5;
        userField = new JTextField("alice", 10);
        panel.add(userField, gbc);

        // Connect button
        gbc.gridx = 6;
        gbc.gridy = 0;
        connectButton = new JButton("Connect");
        connectButton.addActionListener(_ -> connectToServer());
        panel.add(connectButton, gbc);

        return panel;
    }

    private JPanel createCommandPanel() {
        JPanel panel = new JPanel(new FlowLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Commands"));

        lsButton = new JButton("List Files (ls)");
        lsButton.addActionListener(_ -> sendCommand("ls"));
        panel.add(lsButton);

        getButton = new JButton("Get File");
        getButton.addActionListener(_ -> getFile());
        panel.add(getButton);

        disconnectButton = new JButton("Disconnect");
        disconnectButton.addActionListener(_ -> disconnect());
        panel.add(disconnectButton);

        return panel;
    }

    private void updateButtonStates() {
        connectButton.setEnabled(!connected);
        lsButton.setEnabled(connected);
        getButton.setEnabled(connected);
        disconnectButton.setEnabled(connected);
        hostField.setEnabled(!connected);
        portField.setEnabled(!connected);
        userField.setEnabled(!connected);
    }

    private void connectToServer() {
        String host = hostField.getText().trim();
        String portText = portField.getText().trim();
        String userID = userField.getText().trim();

        if (host.isEmpty() || portText.isEmpty() || userID.isEmpty()) {
            showError("Please fill in all connection fields.");
            return;
        }

        try {
            int port = Integer.parseInt(portText);

            // Check if keys exist
            if (!new File("server.pub").exists() ||
                    !new File(userID + ".prv").exists() ||
                    !new File(userID + ".pub").exists()) {
                showError("Error: User or Server keys do not exist.\n" +
                        "Make sure you have:\n" +
                        "- server.pub\n" +
                        "- " + userID + ".prv\n" +
                        "- " + userID + ".pub");
                return;
            }

            appendOutput("Connecting to " + host + ":" + port + " as " + userID + "...\n");

            // Perform initial handshake
            if (performHandshake(host, port, userID)) {
                connected = true;
                updateButtonStates();
                appendOutput("Connected successfully!\n");
                appendOutput("You can now use the command buttons below.\n\n");
            }

        } catch (NumberFormatException e) {
            showError("Invalid port number.");
        } catch (ConnectException e) {
            showError("Cannot connect to server. Make sure the server is running on " + host + ":" + portText);
        } catch (SocketException e) {
            showError("Connection lost during handshake. Server may have rejected the connection.\n" +
                    "Check that:\n" +
                    "1. Server is running\n" +
                    "2. Keys exist and are valid\n" +
                    "3. User '" + userID + "' is authorized");
        } catch (Exception e) {
            showError("Connection failed: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private boolean performHandshake(String host, int port, String userID) throws Exception {
        // Generate 16 random bytes
        SecureRandom rand = new SecureRandom();
        byte[] bytes = new byte[16];
        rand.nextBytes(bytes);

        // Load server public key
        File pub = new File("server.pub");
        byte[] pubBytes = Files.readAllBytes(pub.toPath());
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pubBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey pubKey = kf.generatePublic(keySpec);

        // Load user private key
        File prv = new File(userID + ".prv");
        byte[] prvBytes = Files.readAllBytes(prv.toPath());
        PKCS8EncodedKeySpec prvSpec = new PKCS8EncodedKeySpec(prvBytes);
        KeyFactory kf2 = KeyFactory.getInstance("RSA");
        PrivateKey prvKey = kf2.generatePrivate(prvSpec);

        // Encrypt user ID and bytes
        Cipher encrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        encrypt.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] encryptedID = encrypt.doFinal(userID.getBytes());
        byte[] encryptedBytes = encrypt.doFinal(bytes);

        // Sign the encrypted bytes
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(prvKey);
        signature.update(encryptedBytes);
        byte[] signedBytes = signature.sign();

        // Connect and send data
        socket = new Socket(host, port);
        out = new DataOutputStream(socket.getOutputStream());
        in = new DataInputStream(socket.getInputStream());

        out.write(encryptedID);
        out.write(encryptedBytes);
        out.write(signedBytes);
        out.flush();

        // Receive response
        byte[] encryptedKey = new byte[256];
        int bytesRead1 = in.read(encryptedKey);
        if (bytesRead1 != 256) {
            throw new IOException("Server closed connection during handshake - expected 256 bytes, got " + bytesRead1);
        }
        byte[] signedNewBytes = new byte[256];
        int bytesRead2 = in.read(signedNewBytes);
        if (bytesRead2 != 256) {
            throw new IOException("Server closed connection during handshake - expected 256 bytes, got " + bytesRead2);
        }

        // Decrypt the new key
        Cipher decrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        decrypt.init(Cipher.DECRYPT_MODE, prvKey);
        byte[] decryptedKey = decrypt.doFinal(encryptedKey);

        // Verify signature
        PublicKey serverPubKey = fetchUserKeys("server");
        Signature verified = Signature.getInstance("SHA1withRSA");
        verified.initVerify(serverPubKey);
        verified.update(encryptedKey);
        boolean verification = verified.verify(signedNewBytes);

        // Check verification and key match
        if (verification && Arrays.equals(Arrays.copyOfRange(decryptedKey, 0, 16), bytes)) {
            appendOutput("Signature verified and key generated successfully.\n");

            // Setup AES encryption
            md = MessageDigest.getInstance("MD5");
            initVector = md.digest(decryptedKey);
            aesKey = new SecretKeySpec(decryptedKey, "AES");

            return true;
        } else {
            appendOutput("Signature verification failed, closing connection.\n");
            socket.close();
            return false;
        }
    }

    private void sendCommand(String command) {
        if (!connected) {
            showError("Not connected to server.");
            return;
        }

        try {
            appendOutput("Sending command: " + command + "\n");

            // Encrypt and send command
            byte[] encryptedCommand = encryptCommand(command, aesKey, initVector);
            initVector = md.digest(initVector);
            out.write(encryptedCommand);
            out.flush();

            // Receive response size
            byte[] encSize = new byte[16];
            in.readFully(encSize);
            int byteSize = decryptSize(encSize, aesKey, initVector);

            // Receive and decrypt response
            byte[] encryptedData = new byte[byteSize];
            in.readFully(encryptedData);
            String message = decryptMessage(encryptedData, aesKey, initVector);

            appendOutput("Server response:\n" + message + "\n");

        } catch (Exception e) {
            showError("Error sending command: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void getFile() {
        if (!connected) {
            showError("Not connected to server.");
            return;
        }

        String filename = JOptionPane.showInputDialog(this,
                "Enter filename to download:",
                "Get File",
                JOptionPane.QUESTION_MESSAGE);

        if (filename == null || filename.trim().isEmpty()) {
            return;
        }

        filename = filename.trim();
        String command = "get " + filename;

        try {
            appendOutput("Attempting to fetch file: " + filename + "\n");

            // Encrypt and send command
            byte[] encryptedCommand = encryptCommand(command, aesKey, initVector);
            initVector = md.digest(initVector);
            out.write(encryptedCommand);
            out.flush();

            // Receive response size
            byte[] encSize = new byte[16];
            in.readFully(encSize);
            int byteSize = decryptSize(encSize, aesKey, initVector);

            // Receive and decrypt response
            byte[] encryptedData = new byte[byteSize];
            in.readFully(encryptedData);
            String message = decryptFile(encryptedData, filename, aesKey, initVector);

            appendOutput(message + "\n");

        } catch (Exception e) {
            showError("Error getting file: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void disconnect() {
        try {
            if (connected && socket != null) {
                sendCommand("bye");
                socket.close();
            }
        } catch (Exception e) {
            // Ignore errors during disconnect
        } finally {
            connected = false;
            updateButtonStates();
            appendOutput("Disconnected from server.\n\n");
        }
    }

    // Utility methods from original client
    private PublicKey fetchUserKeys(String userID) throws Exception {
        File pub = new File(userID + ".pub");
        byte[] pubBytes = Files.readAllBytes(pub.toPath());
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pubBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(keySpec);
    }

    private byte[] encryptCommand(String command, SecretKeySpec aesKey, byte[] initVector) throws Exception {
        Cipher encrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        encrypt.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(initVector));
        return encrypt.doFinal(command.getBytes());
    }

    private String decryptMessage(byte[] message, SecretKeySpec aesKey, byte[] initVector) throws Exception {
        Cipher decrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        decrypt.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(initVector));
        byte[] decryptedMessage = decrypt.doFinal(message);
        return new String(decryptedMessage);
    }

    private int decryptSize(byte[] message, SecretKeySpec aesKey, byte[] initVector) throws Exception {
        Cipher decrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        decrypt.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(initVector));
        byte[] decryptedMessage = decrypt.doFinal(message);
        String size = new String(decryptedMessage);
        return Integer.parseInt(size);
    }

    private String decryptFile(byte[] message, String fileName, SecretKeySpec aesKey, byte[] initVector)
            throws Exception {
        Cipher decrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        decrypt.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(initVector));
        byte[] decryptedMessage = decrypt.doFinal(message);

        String errMessage = new String(decryptedMessage);
        if (errMessage.equals("No such file exists")) {
            return errMessage;
        } else {
            try (FileOutputStream fos = new FileOutputStream("CopyOf" + fileName)) {
                fos.write(decryptedMessage);
            }
            return fileName + " has been downloaded as CopyOf" + fileName;
        }
    }

    private void appendOutput(String text) {
        SwingUtilities.invokeLater(() -> {
            outputArea.append(text);
            outputArea.setCaretPosition(outputArea.getDocument().getLength());
        });
    }

    private void showError(String message) {
        JOptionPane.showMessageDialog(this, message, "Error", JOptionPane.ERROR_MESSAGE);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            new ClientGUI().setVisible(true);
        });
    }
}