import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class ExecutableSigner {

    // Generate a key pair (public/private keys)
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    // Sign a file
    public static String signFile(File file, PrivateKey privateKey) throws Exception {
        byte[] fileData = Files.readAllBytes(file.toPath());

        // Hash the file data
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] fileHash = digest.digest(fileData);

        // Sign the hash
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(fileHash);
        byte[] digitalSignature = signature.sign();

        // Return the Base64-encoded signature
        return Base64.getEncoder().encodeToString(digitalSignature);
    }

    // Verify the signature of a file
    public static boolean verifyFile(File file, String signatureString, PublicKey publicKey) throws Exception {
        byte[] fileData = Files.readAllBytes(file.toPath());

        // Hash the file data
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] fileHash = digest.digest(fileData);

        // Decode the Base64 signature
        byte[] digitalSignature = Base64.getDecoder().decode(signatureString);

        // Verify the signature
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(fileHash);
        return signature.verify(digitalSignature);
    }

    // Save the key to a file
    public static void saveKeyToFile(Key key, File file) throws IOException {
        byte[] encodedKey = key.getEncoded();
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(encodedKey);
        }
    }

    // Load a private key from a file
    public static PrivateKey loadPrivateKey(File file) throws Exception {
        byte[] keyBytes = Files.readAllBytes(file.toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(spec);
    }

    // Load a public key from a file
    public static PublicKey loadPublicKey(File file) throws Exception {
        byte[] keyBytes = Files.readAllBytes(file.toPath());
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            JFrame frame = new JFrame("Executable Signer");
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            frame.setSize(600, 400);

            JPanel panel = new JPanel();
            panel.setLayout(new BorderLayout());

            JLabel instructionLabel = new JLabel("Executable Signer Tool", SwingConstants.CENTER);
            instructionLabel.setFont(new Font("Arial", Font.BOLD, 18));
            panel.add(instructionLabel, BorderLayout.NORTH);

            JTextArea outputArea = new JTextArea();
            outputArea.setFont(new Font("Courier New", Font.PLAIN, 14));
            outputArea.setEditable(false);
            JScrollPane scrollPane = new JScrollPane(outputArea);
            panel.add(scrollPane, BorderLayout.CENTER);

            JPanel buttonPanel = new JPanel();
            buttonPanel.setLayout(new GridLayout(1, 3, 10, 10));

            JButton generateKeysButton = new JButton("Generate Keys");
            JButton signButton = new JButton("Sign File");
            JButton verifyButton = new JButton("Verify File");

            buttonPanel.add(generateKeysButton);
            buttonPanel.add(signButton);
            buttonPanel.add(verifyButton);

            panel.add(buttonPanel, BorderLayout.SOUTH);

            frame.add(panel);
            frame.setVisible(true);

            generateKeysButton.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    try {
                        KeyPair keyPair = generateKeyPair();
                        saveKeyToFile(keyPair.getPrivate(), new File("private.key"));
                        saveKeyToFile(keyPair.getPublic(), new File("public.key"));
                        outputArea.append("Keys generated and saved to 'private.key' and 'public.key'.\n");
                    } catch (Exception ex) {
                        outputArea.append("Error generating keys: " + ex.getMessage() + "\n");
                    }
                }
            });

            signButton.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    JFileChooser fileChooser = new JFileChooser();
                    if (fileChooser.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) {
                        File fileToSign = fileChooser.getSelectedFile();
                        try {
                            PrivateKey privateKey = loadPrivateKey(new File("private.key"));
                            String signature = signFile(fileToSign, privateKey);
                            outputArea.append("File signed. Signature: " + signature + "\n");
                        } catch (Exception ex) {
                            outputArea.append("Error signing file: " + ex.getMessage() + "\n");
                        }
                    }
                }
            });

            verifyButton.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    JFileChooser fileChooser = new JFileChooser();
                    if (fileChooser.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) {
                        File fileToVerify = fileChooser.getSelectedFile();
                        String signature = JOptionPane.showInputDialog(frame, "Enter the signature to verify:");
                        try {
                            PublicKey publicKey = loadPublicKey(new File("public.key"));
                            boolean isVerified = verifyFile(fileToVerify, signature, publicKey);
                            outputArea.append("Verification: " + (isVerified ? "Successful" : "Failed") + "\n");
                        } catch (Exception ex) {
                            outputArea.append("Error verifying file: " + ex.getMessage() + "\n");
                        }
                    }
                }
            });
        });
    }
}
