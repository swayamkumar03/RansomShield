package com.ransomshield;

import com.ransomshield.analysis.EntropyCalculator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class EntropyCalculatorTest {

    private EntropyCalculator calculator;

    @BeforeEach
    public void setUp() {
        calculator = new EntropyCalculator();
    }

    @Test
    public void testEmptyByteArray() {
        double entropy = calculator.calculateEntropy(new byte[0]);
        assertEquals(0.0, entropy, 0.001);
    }

    @Test
    public void testNullByteArray() {
        double entropy = calculator.calculateEntropy((byte[]) null);
        assertEquals(0.0, entropy, 0.001);
    }

    @Test
    public void testZeroEntropyUniformBytes() {
        // All bytes identical: e.g. 1000 'A' characters
        byte[] repetitive = new byte[1000];
        Arrays.fill(repetitive, (byte) 'A');
        double entropy = calculator.calculateEntropy(repetitive);
        assertEquals(0.0, entropy, 0.001, "All identical bytes should have exactly 0 entropy");
    }

    @Test
    public void testHighEntropyRandomBytes() {
        // SecureRandom bytes should have entropy approaching 8.0 bits/byte
        byte[] randomBytes = new byte[8192];
        new SecureRandom().nextBytes(randomBytes);
        double entropy = calculator.calculateEntropy(randomBytes);
        assertTrue(entropy >= 7.8 && entropy <= 8.0,
                "Random bytes must have high entropy >= 7.8, but was: " + entropy);
    }

    @Test
    public void testNaturalEnglishTextEntropy() {
        String text = "The quick brown fox jumps over the lazy dog. RansomShield behavioral detection system.";
        double entropy = calculator.calculateEntropy(text.getBytes(StandardCharsets.UTF_8));
        // Typical English ASCII text has entropy between 3.5 and 4.8 bits/byte
        assertTrue(entropy >= 3.0 && entropy <= 5.5,
                "Natural text entropy should be between 3.0 and 5.5, was: " + entropy);
    }

    @Test
    public void testFileEntropyCalculation(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("test.bin");
        byte[] randomData = new byte[4096];
        new SecureRandom().nextBytes(randomData);
        Files.write(file, randomData);

        double fileEntropy = calculator.calculateEntropy(file);
        assertTrue(fileEntropy >= 7.7, "File entropy should match high random data: " + fileEntropy);
    }

    @Test
    public void testNonExistentFileReturnsZero() {
        Path missing = Path.of("non_existent_file_123456789.dat");
        double entropy = calculator.calculateEntropy(missing);
        assertEquals(0.0, entropy, 0.001);
    }
}
