 static int[] IP, FP, E, P, PC1, PC2, SHIFTS;
    static int[][][] SBOX = new int[8][4][16];
    static void loadTables() throws Exception {

        java.io.BufferedReader file =
            new java.io.BufferedReader(
                new java.io.FileReader("DES_Tables.txt"));

        String line;

        while ((line = file.readLine()) != null) {

            line = line.trim();

            if (line.isEmpty() || !line.contains("="))
                continue;

            String[] parts = line.split("=", 2);
            String name = parts[0].trim();

            int[] values = readArray(parts[1]);

            switch (name) {
                case "IP": IP = values; break;
                case "FP": FP = values; break;
                case "E": E = values; break;
                case "P": P = values; break;
                case "PC1": PC1 = values; break;
                case "PC2": PC2 = values; break;
                case "SHIFTS": SHIFTS = values; break;

                case "SBOX":
                    if (values.length != 512)
                        throw new Exception("Invalid SBOX table");

                    int k = 0;

                    for (int b = 0; b < 8; b++)
                        for (int r = 0; r < 4; r++)
                            for (int c = 0; c < 16; c++)
                                SBOX[b][r][c] = values[k++];
                    break;
            }
        }

        file.close();

        if (IP == null || FP == null || E == null ||
            P == null || PC1 == null || PC2 == null ||
            SHIFTS == null)
            throw new Exception("Missing DES table");
    }

    // Convert comma-separated numbers to array
    static int[] readArray(String data) {

        String[] parts = data.trim().split(",");
        int[] result = new int[parts.length];

        for (int i = 0; i < parts.length; i++)
            result[i] = Integer.parseInt(parts[i].trim());

        return result;
    }
    static String textToBinary(String text) throws Exception {

        byte[] bytes = text.getBytes("UTF-8");
        StringBuilder result = new StringBuilder();

        for (byte b : bytes) {

            int value = b & 255;

            for (int i = 7; i >= 0; i--)
                result.append((value >> i) & 1);
        }

        return result.toString();
    }

    // Convert binary to hexadecimal
    static String binaryToHex(String binary) {

        String digits = "0123456789ABCDEF";
        StringBuilder result = new StringBuilder();

        for (int i = 0; i < binary.length(); i += 4) {

            int value = 0;

            for (int j = 0; j < 4; j++)
                value = value * 2 + binary.charAt(i + j) - '0';

            result.append(digits.charAt(value));
        }

        return result.toString();
    }
    static String binaryToText(String binary) throws Exception {

        byte[] bytes = new byte[binary.length() / 8];

        for (int i = 0; i < bytes.length; i++) {

            int value = 0;

            for (int j = 0; j < 8; j++)
                value = value * 2 +
                    binary.charAt(i * 8 + j) - '0';

            bytes[i] = (byte) value;
        }

        return new String(bytes, "UTF-8");
    }

    // Convert integer to 8-bit binary
    static String to8Bits(int value) {

        String result = "";

        for (int i = 7; i >= 0; i--)
            result += (value >> i) & 1;

        return result;
    }

    // Apply padding
    static String applyPadding(String binary) {

        int count = 8 - (binary.length() / 8 % 8);
        StringBuilder result = new StringBuilder(binary);

        for (int i = 0; i < count; i++)
            result.append(to8Bits(count));

        return result.toString();
    }

    // Remove padding
    static String removePadding(String binary) {

        if (binary.isEmpty() || binary.length() % 8 != 0)
            throw new IllegalArgumentException("Invalid data");

        int count = Integer.parseInt(
            binary.substring(binary.length() - 8), 2);

        if (count < 1 || count > 8 ||
            count * 8 > binary.length())
            throw new IllegalArgumentException("Invalid padding");

        String padding = to8Bits(count);

        for (int i = 0; i < count; i++) {

            int start = binary.length() - (i + 1) * 8;

            if (!binary.substring(start, start + 8).equals(padding))
                throw new IllegalArgumentException("Invalid padding");
        }

        return binary.substring(0, binary.length() - count * 8);
    }

    // Circular left shift
    static String leftShift(String value, int count) {
        return value.substring(count) + value.substring(0, count);
    }

    // Apply permutation table
    static String permute(String input, int[] table) {

        StringBuilder result = new StringBuilder();

        for (int position : table)
            result.append(input.charAt(position - 1));

        return result.toString();
    }

    // XOR
    static String xor(String a, String b) {

        StringBuilder result = new StringBuilder();

        for (int i = 0; i < a.length(); i++)
            result.append(a.charAt(i) == b.charAt(i) ? '0' : '1');

        return result.toString();
    }

    // Generate 16 DES subkeys
    static String[] generateSubkeys(String key) {

        String selected = permute(key, PC1);

        String left = selected.substring(0, 28);
        String right = selected.substring(28);

        String[] keys = new String[16];

        for (int i = 0; i < 16; i++) {

            left = leftShift(left, SHIFTS[i]);
            right = leftShift(right, SHIFTS[i]);

            keys[i] = permute(left + right, PC2);
        }

        return keys;
    }

    // S-Box substitution
    static String sBoxSubstitution(String input) {

        StringBuilder result = new StringBuilder();

        for (int i = 0; i < 8; i++) {

            String block = input.substring(i * 6, i * 6 + 6);

            int row = Integer.parseInt(
                "" + block.charAt(0) + block.charAt(5), 2);

            int col = Integer.parseInt(block.substring(1, 5), 2);

            result.append(to4Bits(SBOX[i][row][col]));
        }

        return result.toString();
    }

    // Convert integer to 4-bit binary
    static String to4Bits(int value) {

        String result = "";

        for (int i = 3; i >= 0; i--)
            result += (value >> i) & 1;

        return result;
    }

    // Feistel function
    static String feistel(String right, String key) {

        String expanded = permute(right, E);
        String mixed = xor(expanded, key);
        String substituted = sBoxSubstitution(mixed);

        return permute(substituted, P);
    }

    // DES encryption and decryption rounds
    static String processBlock(String block, String[] keys,
                               boolean decrypt) {

        String data = permute(block, IP);

        String left = data.substring(0, 32);
        String right = data.substring(32);

        for (int i = 0; i < 16; i++) {

            int index = decrypt ? 15 - i : i;

            String newRight = xor(left, feistel(right, keys[index]));

            left = right;
            right = newRight;
        }

        return permute(right + left, FP);
    }

    // Main
    public static void main(String[] args) {

        java.io.BufferedReader input =
            new java.io.BufferedReader(
                new java.io.InputStreamReader(System.in));

        try {

            loadTables();

    
            System.out.println("       DES ENCRYPTION SYSTEM");
          

            System.out.print("Enter Plaintext: ");
            String plaintext = input.readLine();

            System.out.print("Enter Key (exactly 8 ASCII characters): ");
            String key = input.readLine();

            boolean valid = key.length() == 8;

            for (int i = 0; i < key.length(); i++)
                if (key.charAt(i) > 127)
                    valid = false;

            if (!valid) {
                System.out.println(
                    "Error: Key must contain exactly 8 ASCII characters.");
                return;
            }
            System.out.println("\n===== ORIGINAL TEXT =====");
            System.out.println(plaintext);

            // Padding
            String originalBinary = textToBinary(plaintext);
            String paddedBinary = applyPadding(originalBinary);

            System.out.println("\n===== PADDING =====");
            System.out.println("Original length: " +
                originalBinary.length() / 8 + " bytes");
            System.out.println("Padded text length: " +
                paddedBinary.length() / 8 + " bytes");

            // Binary conversion
            String keyBinary = textToBinary(key);

            System.out.println("\n===== BINARY CONVERSION =====");
            System.out.println("Plaintext Binary:");
            System.out.println(paddedBinary);
            System.out.println("\nKey Binary:");
            System.out.println(keyBinary);

            // Key generation
            String[] keys = generateSubkeys(keyBinary);

            System.out.println("\n===== KEY GENERATION =====");

            for (int i = 0; i < 16; i++)
                System.out.println("K" + (i + 1) + ": " + keys[i]);

            // Encryption
            System.out.println("\n===== ENCRYPTION =====");

            StringBuilder ciphertext = new StringBuilder();
            int blockNumber = 1;

            for (int i = 0; i < paddedBinary.length(); i += 64) {

                String block = paddedBinary.substring(i, i + 64);
                String encrypted = processBlock(block, keys, false);

                ciphertext.append(encrypted);

                System.out.println("\n===== BLOCK " + blockNumber + " =====");
                System.out.println("Input Block:");
                System.out.println(block);
                System.out.println("Encrypted Block Binary:");
                System.out.println(encrypted);
                System.out.println("Encrypted Block Hex:");
                System.out.println(binaryToHex(encrypted));

                blockNumber++;
            }

            String cipherHex = binaryToHex(ciphertext.toString());

            System.out.println("\n===== FINAL ENCRYPTION RESULT =====");
            System.out.println("Ciphertext (Hex):");
            System.out.println(cipherHex);

            // Decryption
            System.out.println("\n===== DECRYPTION =====");

            StringBuilder decrypted = new StringBuilder();
            blockNumber = 1;

            for (int i = 0; i < ciphertext.length(); i += 64) {

                String block = ciphertext.substring(i, i + 64);
                String result = processBlock(block, keys, true);

                decrypted.append(result);

                System.out.println("\n===== DECRYPT BLOCK " +
                    blockNumber + " =====");
                System.out.println("Cipher Block Hex:");
                System.out.println(binaryToHex(block));
                System.out.println("Decrypted Block Binary:");
                System.out.println(result);
                System.out.println("Decrypted Block Hex:");
                System.out.println(binaryToHex(result));

                blockNumber++;
            }

            // Remove padding
            System.out.println("\n===== REMOVE PADDING =====");

            int padding = Integer.parseInt(
                decrypted.substring(decrypted.length() - 8), 2);

            String finalBinary = removePadding(decrypted.toString());

            System.out.println("Padding bytes found: " + padding);
            System.out.println("Length after removing padding: " +
                finalBinary.length() / 8 + " bytes");

            // Final result
            String decryptedText = binaryToText(finalBinary);

            System.out.println("\n===== FINAL DECRYPTION RESULT =====");
            System.out.println("Decrypted Text:");
            System.out.println(decryptedText);

            // Verification
            System.out.println("\n===== VERIFICATION =====");

            if (plaintext.equals(decryptedText))
                System.out.println(
                    "SUCCESS: Decrypted text matches the original plaintext.");
            else
                System.out.println(
                    "FAILED: Decrypted text does not match the original plaintext.");

        } catch (Exception e) {

            System.out.println("Error: " + e.getMessage());
        }
    }
