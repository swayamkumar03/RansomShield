package com.ransomshield.simulator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Generates structured test files and folders for safe simulation demonstrations.
 */
public class TestDataGenerator {
    private static final Logger logger = LoggerFactory.getLogger(TestDataGenerator.class);

    private final Path testRoot;

    public TestDataGenerator(Path testRoot) {
        this.testRoot = testRoot.toAbsolutePath().normalize();
    }

    /**
     * Initializes the standard directory structure with approximately 100 benign test files.
     */
    public List<Path> generateStandardDataset() throws IOException {
        Files.createDirectories(testRoot);

        List<Path> createdFiles = new ArrayList<>();

        Path docsDir = testRoot.resolve("Documents");
        Path imagesDir = testRoot.resolve("Images");
        Path reportsDir = testRoot.resolve("Reports");
        Path projectsDir = testRoot.resolve("Projects");

        Files.createDirectories(docsDir);
        Files.createDirectories(imagesDir);
        Files.createDirectories(reportsDir);
        Files.createDirectories(projectsDir);

        // 1. Documents (30 files: .txt, .docx-like, .pdf-like)
        for (int i = 1; i <= 30; i++) {
            Path file = docsDir.resolve(String.format("document_%02d.txt", i));
            String content = "RansomShield Document " + i + "\nThis is a standard text file with normal English entropy.\n"
                    + "Quarterly business notes, memos, project planning objectives, and general communications.\n".repeat(5);
            Files.writeString(file, content, StandardCharsets.UTF_8);
            createdFiles.add(file);
        }

        // 2. Images (30 files: mock image / binary data with moderate structure)
        for (int i = 1; i <= 30; i++) {
            Path file = imagesDir.resolve(String.format("photo_%02d.jpg", i));
            byte[] mockImage = ("JPEG_MOCK_HEADER_DATA_IMAGE_" + i + "\n").getBytes(StandardCharsets.UTF_8);
            byte[] body = new byte[1024];
            for (int b = 0; b < body.length; b++) {
                body[b] = (byte) ((b + i) % 64 + 32); // moderate structured ASCII-like bytes
            }
            byte[] combined = new byte[mockImage.length + body.length];
            System.arraycopy(mockImage, 0, combined, 0, mockImage.length);
            System.arraycopy(body, 0, combined, mockImage.length, body.length);
            Files.write(file, combined);
            createdFiles.add(file);
        }

        // 3. Reports (20 files: .csv, .log)
        for (int i = 1; i <= 20; i++) {
            Path file = reportsDir.resolve(String.format("financial_report_%02d.csv", i));
            StringBuilder sb = new StringBuilder("id,date,account,amount,status,category\n");
            for (int r = 1; r <= 25; r++) {
                sb.append(String.format("%d,2026-10-%02d,ACC-%04d,%.2f,APPROVED,Operations\n", r, (r % 28) + 1, r * 10, r * 123.45));
            }
            Files.writeString(file, sb.toString(), StandardCharsets.UTF_8);
            createdFiles.add(file);
        }

        // 4. Projects (20 files: source/config files)
        for (int i = 1; i <= 20; i++) {
            Path file = projectsDir.resolve(String.format("config_module_%02d.json", i));
            String json = String.format("{\n  \"moduleId\": %d,\n  \"name\": \"Module-%02d\",\n  \"enabled\": true,\n  \"retryLimit\": 3\n}\n", i, i);
            Files.writeString(file, json, StandardCharsets.UTF_8);
            createdFiles.add(file);
        }

        logger.info("Generated standard test dataset with {} files across 4 directories in {}", createdFiles.size(), testRoot);
        return createdFiles;
    }

    public Path getTestRoot() {
        return testRoot;
    }

    public static void main(String[] args) throws IOException {
        Path target = args.length > 0 ? Path.of(args[0]) : Path.of("./test-data");
        TestDataGenerator gen = new TestDataGenerator(target);
        gen.generateStandardDataset();
        System.out.println("Generated standard test dataset in " + target.toAbsolutePath().normalize());
    }
}
