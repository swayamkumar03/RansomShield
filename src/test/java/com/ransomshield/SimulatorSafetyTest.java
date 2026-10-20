package com.ransomshield;

import com.ransomshield.simulator.RansomwareSimulator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

public class SimulatorSafetyTest {

    @Test
    public void testNullPathThrowsSecurityException() {
        assertThrows(SecurityException.class, () -> {
            RansomwareSimulator.validateSafeTestDirectory(null);
        });
    }

    @Test
    public void testRootDirectoryThrowsSecurityException() {
        Path root = Paths.get("/").toAbsolutePath().normalize();
        assertThrows(SecurityException.class, () -> {
            RansomwareSimulator.validateSafeTestDirectory(root);
        });
    }

    @Test
    public void testUserHomeDirectoryThrowsSecurityException() {
        String userHome = System.getProperty("user.home");
        assertNotNull(userHome);
        Path homePath = Paths.get(userHome);

        assertThrows(SecurityException.class, () -> {
            RansomwareSimulator.validateSafeTestDirectory(homePath);
        });
    }

    @Test
    public void testSystemPathThrowsSecurityException() {
        Path winPath = Paths.get("C:/Windows/System32");
        assertThrows(SecurityException.class, () -> {
            RansomwareSimulator.validateSafeTestDirectory(winPath);
        });
    }

    @Test
    public void testAllowedTestDirectorySucceeds(@TempDir Path tempDir) {
        Path safeDir = tempDir.resolve("safe-sandbox-test");
        assertDoesNotThrow(() -> {
            Path validated = RansomwareSimulator.validateSafeTestDirectory(safeDir);
            assertNotNull(validated);
        });
    }
}
