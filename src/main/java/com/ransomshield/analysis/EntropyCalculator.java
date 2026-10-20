package com.ransomshield.analysis;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Calculates Shannon entropy on file contents and byte arrays.
 * 
 * Shannon Entropy Formula:
 * H(X) = -SUM( P(x_i) * log2(P(x_i)) ) for i in 0..255
 * 
 * Output range is 0.0 (completely uniform/repetitive) to 8.0 (completely random/encrypted).
 */
public class EntropyCalculator {
    private static final Logger logger = LoggerFactory.getLogger(EntropyCalculator.class);
    private static final double LOG_2 = Math.log(2);
    private static final int BUFFER_SIZE = 64 * 1024; // 64 KB

    private final long maxBytesToRead;

    public EntropyCalculator() {
        this(25 * 1024 * 1024L); // default 25MB maximum sample
    }

    public EntropyCalculator(long maxBytesToRead) {
        this.maxBytesToRead = maxBytesToRead > 0 ? maxBytesToRead : 25 * 1024 * 1024L;
    }

    /**
     * Calculates Shannon entropy directly from a byte array.
     *
     * @param data Byte array to evaluate
     * @return Entropy value between 0.0 and 8.0
     */
    public double calculateEntropy(byte[] data) {
        if (data == null || data.length == 0) {
            return 0.0;
        }

        long[] frequencies = new long[256];
        for (byte b : data) {
            frequencies[b & 0xFF]++;
        }

        return computeEntropyFromFrequencies(frequencies, data.length);
    }

    /**
     * Calculates Shannon entropy from a file path using streaming buffered I/O.
     * Handles locked, disappearing, or permission-denied files gracefully.
     *
     * @param path File to analyze
     * @return Entropy value between 0.0 and 8.0, or 0.0 if unreadable
     */
    public double calculateEntropy(Path path) {
        if (path == null) {
            return 0.0;
        }

        try {
            if (!Files.exists(path) || !Files.isRegularFile(path)) {
                return 0.0;
            }

            long fileSize = Files.size(path);
            if (fileSize == 0) {
                return 0.0;
            }

            long[] frequencies = new long[256];
            long totalBytesRead = 0;
            byte[] buffer = new byte[BUFFER_SIZE];

            try (InputStream is = Files.newInputStream(path);
                 BufferedInputStream bis = new BufferedInputStream(is, BUFFER_SIZE)) {

                int bytesRead;
                while ((bytesRead = bis.read(buffer)) != -1) {
                    for (int i = 0; i < bytesRead; i++) {
                        frequencies[buffer[i] & 0xFF]++;
                    }
                    totalBytesRead += bytesRead;

                    if (totalBytesRead >= maxBytesToRead) {
                        logger.debug("Reached max sample size {} bytes for file {}", maxBytesToRead, path.getFileName());
                        break;
                    }
                }
            }

            if (totalBytesRead == 0) {
                return 0.0;
            }

            return computeEntropyFromFrequencies(frequencies, totalBytesRead);

        } catch (Exception e) {
            // File might have been locked by another process or deleted immediately after event
            logger.debug("Could not compute entropy for {}: {}", path.getFileName(), e.getMessage());
            return 0.0;
        }
    }

    private double computeEntropyFromFrequencies(long[] frequencies, long totalBytes) {
        double entropy = 0.0;
        for (long count : frequencies) {
            if (count > 0) {
                double p = (double) count / totalBytes;
                entropy -= p * (Math.log(p) / LOG_2);
            }
        }

        // Clamp between 0.0 and 8.0 to eliminate minor floating-point inaccuracies
        return Math.max(0.0, Math.min(8.0, entropy));
    }
}
