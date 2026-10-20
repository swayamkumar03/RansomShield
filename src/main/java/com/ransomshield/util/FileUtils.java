package com.ransomshield.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.*;
import java.util.Comparator;

/**
 * File system utility methods with safety and error resilience.
 */
public class FileUtils {
    private static final Logger logger = LoggerFactory.getLogger(FileUtils.class);

    private FileUtils() {}

    /**
     * Safely reads the size of a file, returning 0 on error or non-existence.
     */
    public static long getFileSizeSafely(Path path) {
        if (path == null) return 0L;
        try {
            if (Files.exists(path) && Files.isRegularFile(path)) {
                return Files.size(path);
            }
        } catch (Exception e) {
            // Locked or disappearing file
        }
        return 0L;
    }

    /**
     * Formats bytes into a human-readable string (e.g. 1.2 KB, 4.5 MB).
     */
    public static String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        int exp = (int) (Math.log(bytes) / Math.log(1024));
        char pre = "KMGTPE".charAt(exp - 1);
        return String.format("%.1f %sB", bytes / Math.pow(1024, exp), pre);
    }

    /**
     * Deletes a directory and its contents recursively, strictly ensuring that the directory
     * is not empty/root and resides safely under an allowed boundary.
     */
    public static void deleteRecursivelySafely(Path target, Path safeRoot) throws IOException {
        if (target == null || safeRoot == null) {
            throw new IllegalArgumentException("Target and safeRoot must not be null");
        }

        Path normalizedTarget = target.toAbsolutePath().normalize();
        Path normalizedRoot = safeRoot.toAbsolutePath().normalize();

        if (!normalizedTarget.startsWith(normalizedRoot)) {
            throw new SecurityException("Refusing to delete path outside safe root: " + normalizedTarget);
        }

        if (normalizedTarget.equals(normalizedTarget.getRoot())) {
            throw new SecurityException("Refusing to delete filesystem root: " + normalizedTarget);
        }

        if (!Files.exists(normalizedTarget)) {
            return;
        }

        Files.walk(normalizedTarget)
                .sorted(Comparator.reverseOrder())
                .forEach(path -> {
                    try {
                        Files.deleteIfExists(path);
                    } catch (IOException e) {
                        logger.warn("Could not delete file during cleanup: {}", path, e);
                    }
                });
    }
}
