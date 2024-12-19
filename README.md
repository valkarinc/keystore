# KeyStore Program

An open-source, basic functional KeyStore program written in Java. This repository includes tools for signing and authenticating files or data using cryptographic methods and managing Java JAR file signing via GUI.

## Features

### 1. **ExecutableSigner.java**
- **Key Pair Generation**: Generates RSA key pairs (public/private keys).
- **Data Signing**: Signs data using private keys.
- **Signature Verification**: Verifies data integrity and authenticity using public keys.

### 2. **JarSignerGUI.java**
- **Graphical Interface**: User-friendly GUI built with Swing for signing JAR files.
- **Integration with KeyTool and JarSigner**: Provides an interface to Java's `keytool` and `jarsigner` commands.
- **Input Fields**:
  - JAR File Path
  - Keystore Name
  - Keystore Password
  - Alias and Signature Info
- **Ease of Use**: Allows users to manage and sign JAR files with minimal command-line interaction.

## Prerequisites
- Java Development Kit (JDK) installed (version 8 or higher).
- Basic knowledge of Java Keystores and cryptographic concepts.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/valkarinc/keystore.git
   cd keystore
   ```
2. Compile the Java files:
   ```bash
   javac ExecutableSigner.java JarSignerGUI.java
   ```
3. Run the GUI application:
   ```bash
   java JarSignerGUI
   ```

## Usage
### Using the GUI
1. Launch the `JarSignerGUI` application.
2. Fill in the required fields (JAR path, keystore name, password, etc.).
3. Click the appropriate button to sign the JAR file or manage the keystore.

### Programmatic Usage
- Utilize the `ExecutableSigner` class to:
  - Generate key pairs.
  - Sign data programmatically.
  - Verify data signatures in your Java applications.

## Example Code
### Generating a Key Pair
```java
KeyPair keyPair = ExecutableSigner.generateKeyPair();
```

### Signing Data
```java
byte[] signature = ExecutableSigner.signData(data, privateKey);
```

### Verifying a Signature
```java
boolean isVerified = ExecutableSigner.verifySignature(data, signature, publicKey);
```

## Contributions
Contributions are welcome! Feel free to submit a pull request or report issues.

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.

---

Thank you for using the KeyStore Program! If you have any questions or feedback, feel free to reach out.
