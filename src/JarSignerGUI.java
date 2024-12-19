import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.util.*;
import java.util.zip.*;
import java.security.*;

public class JarSignerGUI extends JFrame {
    private static final String KEYTOOL_CMD = "keytool";
    private static final String JARSIGNER_CMD = "jarsigner";

    private JTextField jarPathField;
    private JTextField keystoreNameField;
    private JPasswordField keystorePasswordField;
    private JTextField aliasField;
    private JTextField nameField;
    private JTextField organizationField;
    private JTextArea logArea;
    private JButton browseButton;
    private JButton signButton;
    private JButton verifyButton;

    public JarSignerGUI() {
        setTitle("JAR Signer Tool");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setupUI();
        pack();
        setLocationRelativeTo(null);
    }

    private void setupUI() {
        setLayout(new BorderLayout(10, 10));

        // Input Panel
        JPanel inputPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);

        // JAR File Selection
        gbc.gridx = 0; gbc.gridy = 0;
        inputPanel.add(new JLabel("JAR File:"), gbc);

        gbc.gridx = 1;
        jarPathField = new JTextField(30);
        inputPanel.add(jarPathField, gbc);

        gbc.gridx = 2;
        browseButton = new JButton("Browse");
        inputPanel.add(browseButton, gbc);

        // Keystore Name
        gbc.gridx = 0; gbc.gridy = 1;
        inputPanel.add(new JLabel("Keystore Name:"), gbc);

        gbc.gridx = 1; gbc.gridwidth = 2;
        keystoreNameField = new JTextField("keystore.jks");
        inputPanel.add(keystoreNameField, gbc);

        // Keystore Password
        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 1;
        inputPanel.add(new JLabel("Keystore Password:"), gbc);

        gbc.gridx = 1; gbc.gridwidth = 2;
        keystorePasswordField = new JPasswordField();
        inputPanel.add(keystorePasswordField, gbc);

        // Alias
        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 1;
        inputPanel.add(new JLabel("Alias:"), gbc);

        gbc.gridx = 1; gbc.gridwidth = 2;
        aliasField = new JTextField("mykey");
        inputPanel.add(aliasField, gbc);

        // Certificate Information
        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 1;
        inputPanel.add(new JLabel("Full Name:"), gbc);

        gbc.gridx = 1; gbc.gridwidth = 2;
        nameField = new JTextField();
        inputPanel.add(nameField, gbc);

        gbc.gridx = 0; gbc.gridy = 5; gbc.gridwidth = 1;
        inputPanel.add(new JLabel("Organization:"), gbc);

        gbc.gridx = 1; gbc.gridwidth = 2;
        organizationField = new JTextField();
        inputPanel.add(organizationField, gbc);

        // Buttons Panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        signButton = new JButton("Sign JAR");
        verifyButton = new JButton("Verify JAR");
        buttonPanel.add(signButton);
        buttonPanel.add(verifyButton);

        // Log Area
        logArea = new JTextArea(10, 40);
        logArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(logArea);

        // Add all components to frame
        add(inputPanel, BorderLayout.NORTH);
        add(buttonPanel, BorderLayout.CENTER);
        add(scrollPane, BorderLayout.SOUTH);

        // Add listeners
        setupListeners();
    }

    private void setupListeners() {
        browseButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setFileFilter(new javax.swing.filechooser.FileFilter() {
                public boolean accept(File f) {
                    return f.isDirectory() || f.getName().toLowerCase().endsWith(".jar");
                }
                public String getDescription() {
                    return "JAR Files (*.jar)";
                }
            });

            if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                jarPathField.setText(fileChooser.getSelectedFile().getAbsolutePath());
            }
        });

        signButton.addActionListener(e -> new Thread(() -> {
            try {
                signJar();
            } catch (Exception ex) {
                logError("Error during signing: " + ex.getMessage());
            }
        }).start());

        verifyButton.addActionListener(e -> new Thread(() -> {
            try {
                verifyJar();
            } catch (Exception ex) {
                logError("Error during verification: " + ex.getMessage());
            }
        }).start());
    }

    private void signJar() throws IOException, InterruptedException {
        String jarPath = jarPathField.getText();
        String keystoreName = keystoreNameField.getText();
        String keystorePassword = new String(keystorePasswordField.getPassword());
        String alias = aliasField.getText();

        // Validate inputs
        if (jarPath.isEmpty() || keystoreName.isEmpty() || keystorePassword.isEmpty() || alias.isEmpty()) {
            logError("All fields are required!");
            return;
        }

        // Delete existing keystore if it exists
        File keystoreFile = new File(keystoreName);
        if (keystoreFile.exists()) {
            keystoreFile.delete();
        }

        // Create new keystore
        log("Creating new keystore...");
        createKeystore(keystoreName, keystorePassword, alias);

        // Clean the JAR first
        log("Cleaning JAR file of existing signatures and duplicates...");
        try {
            cleanAndCopyJar(jarPath);
            log("JAR file cleaned successfully");
        } catch (IOException e) {
            logError("Error cleaning JAR: " + e.getMessage());
            return;
        }

        // Sign the JAR
        log("Signing JAR file...");
        ProcessBuilder pb = new ProcessBuilder(
                JARSIGNER_CMD,
                "-keystore", keystoreName,
                "-storepass", keystorePassword,
                "-digestalg", "SHA-256",
                "-sigalg", "SHA256withRSA",
                jarPath,
                alias
        );

        Process process = pb.start();
        StreamGobbler errorGobbler = new StreamGobbler(process.getErrorStream(), this::logError);
        StreamGobbler outputGobbler = new StreamGobbler(process.getInputStream(), this::log);

        errorGobbler.start();
        outputGobbler.start();

        int result = process.waitFor();

        if (result == 0) {
            log("JAR signed successfully!");
        } else {
            logError("Failed to sign JAR");
        }
    }

    private void cleanAndCopyJar(String jarPath) throws IOException {
        File tempJar = new File(jarPath + ".tmp");
        Set<String> skipEntries = new HashSet<>(Arrays.asList(
                "META-INF/runelite-client.kotlin_module",
                "META-INF/*.SF",
                "META-INF/*.RSA",
                "META-INF/*.DSA",
                "META-INF/*.EC"
        ));

        try (ZipFile zipFile = new ZipFile(jarPath);
             ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(tempJar))) {

            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            Set<String> processedEntries = new HashSet<>();

            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String entryName = entry.getName();

                // Skip signature files and duplicates
                boolean shouldSkip = false;
                for (String pattern : skipEntries) {
                    if (pattern.contains("*")) {
                        String regex = pattern.replace(".", "\\.").replace("*", ".*");
                        if (entryName.matches(regex)) {
                            shouldSkip = true;
                            break;
                        }
                    } else if (entryName.equals(pattern)) {
                        shouldSkip = true;
                        break;
                    }
                }

                if (shouldSkip || processedEntries.contains(entryName)) {
                    log("Skipping entry: " + entryName);
                    continue;
                }

                processedEntries.add(entryName);
                ZipEntry newEntry = new ZipEntry(entryName);
                zos.putNextEntry(newEntry);

                try (InputStream is = zipFile.getInputStream(entry)) {
                    byte[] buffer = new byte[8192];
                    int len;
                    while ((len = is.read(buffer)) > 0) {
                        zos.write(buffer, 0, len);
                    }
                }
                zos.closeEntry();
            }
        }

        // Replace original JAR with cleaned version
        File originalFile = new File(jarPath);
        if (!originalFile.delete()) {
            throw new IOException("Could not delete original JAR file");
        }
        if (!tempJar.renameTo(originalFile)) {
            throw new IOException("Could not replace original JAR with cleaned version");
        }
        log("JAR file cleaned successfully");
    }

    private void createKeystore(String keystoreName, String password, String alias)
            throws IOException, InterruptedException {
        String name = nameField.getText().trim();
        String organization = organizationField.getText().trim();

        if (name.isEmpty() || organization.isEmpty()) {
            throw new IOException("Please fill in your name and organization");
        }

        ProcessBuilder pb = new ProcessBuilder(
                KEYTOOL_CMD,
                "-genkey",
                "-keystore", keystoreName,
                "-alias", alias,
                "-keyalg", "RSA",
                "-keysize", "2048",
                "-validity", "3650",
                "-storepass", password,
                "-dname", String.format("CN=%s, OU=%s, O=%s, L=Unknown, ST=Unknown, C=US",
                name, organization, organization)
        );

        Process process = pb.start();
        StreamGobbler errorGobbler = new StreamGobbler(process.getErrorStream(), this::logError);
        StreamGobbler outputGobbler = new StreamGobbler(process.getInputStream(), this::log);

        errorGobbler.start();
        outputGobbler.start();

        int result = process.waitFor();

        if (result != 0) {
            throw new IOException("Failed to create keystore");
        }
    }

    private void verifyJar() throws IOException, InterruptedException {
        String jarPath = jarPathField.getText();
        String keystoreName = keystoreNameField.getText();

        log("Verifying JAR signature...");
        ProcessBuilder pb = new ProcessBuilder(
                JARSIGNER_CMD,
                "-verify",
                "-verbose",
                "-certs",
                "-keystore", keystoreName,
                jarPath
        );

        Process process = pb.start();
        StreamGobbler errorGobbler = new StreamGobbler(process.getErrorStream(), this::logError);
        StreamGobbler outputGobbler = new StreamGobbler(process.getInputStream(), this::log);

        errorGobbler.start();
        outputGobbler.start();

        int result = process.waitFor();

        if (result == 0) {
            log("JAR verification successful!");
        } else {
            logError("JAR verification failed");
        }
    }

    private void log(String message) {
        SwingUtilities.invokeLater(() -> {
            logArea.append(message + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }

    private void logError(String message) {
        SwingUtilities.invokeLater(() -> {
            logArea.append("ERROR: " + message + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }

    // Helper class to handle process output streams
    private static class StreamGobbler extends Thread {
        private final InputStream inputStream;
        private final Consumer<String> consumer;

        public StreamGobbler(InputStream inputStream, Consumer<String> consumer) {
            this.inputStream = inputStream;
            this.consumer = consumer;
        }

        @Override
        public void run() {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    consumer.accept(line);
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    @FunctionalInterface
    interface Consumer<T> {
        void accept(T t);
    }

    public static void main(String[] args) {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            e.printStackTrace();
        }

        SwingUtilities.invokeLater(() -> {
            new JarSignerGUI().setVisible(true);
        });
    }
}