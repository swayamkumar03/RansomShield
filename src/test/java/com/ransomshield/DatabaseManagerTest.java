package com.ransomshield;

import com.ransomshield.database.DatabaseManager;
import com.ransomshield.database.FileEventRepository;
import com.ransomshield.database.IncidentRepository;
import com.ransomshield.model.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class DatabaseManagerTest {

    private DatabaseManager dbManager;
    private IncidentRepository incidentRepo;
    private FileEventRepository fileEventRepo;

    @BeforeEach
    public void setUp(@TempDir Path tempDir) {
        Path dbPath = tempDir.resolve("test_ransomshield.db");
        String jdbcUrl = "jdbc:sqlite:" + dbPath.toAbsolutePath();
        dbManager = new DatabaseManager(jdbcUrl);
        incidentRepo = new IncidentRepository(dbManager);
        fileEventRepo = new FileEventRepository(dbManager);
    }

    @Test
    public void testSaveAndRetrieveIncident() {
        Incident incident = new Incident(
                "inc-001",
                Instant.now(),
                ThreatLevel.CRITICAL,
                88,
                "C:/RansomShield-Test",
                65,
                4,
                7.84,
                7.92,
                22.5,
                "High entropy; Rapid modification burst; Multi-directory traversal",
                IncidentStatus.DETECTED,
                List.of("High entropy", "Rapid modification burst", "Multi-directory traversal")
        );

        incidentRepo.save(incident);

        List<Incident> all = incidentRepo.findAll();
        assertEquals(1, all.size());

        Incident retrieved = all.get(0);
        assertEquals("inc-001", retrieved.getId());
        assertEquals(ThreatLevel.CRITICAL, retrieved.getSeverity());
        assertEquals(88, retrieved.getScore());
        assertEquals(65, retrieved.getFilesAffected());
        assertEquals(4, retrieved.getDirectoriesAffected());
        assertEquals(IncidentStatus.DETECTED, retrieved.getStatus());
    }

    @Test
    public void testFilterBySeverity() {
        Incident incNormal = new Incident(
                "inc-norm", Instant.now(), ThreatLevel.NORMAL, 15, "C:/Test", 2, 1, 4.2, 4.2, 0.5,
                "Normal", IncidentStatus.RESOLVED, List.of()
        );
        Incident incCrit = new Incident(
                "inc-crit", Instant.now(), ThreatLevel.CRITICAL, 90, "C:/Test", 90, 4, 7.8, 7.9, 25.0,
                "Critical", IncidentStatus.DETECTED, List.of()
        );

        incidentRepo.save(incNormal);
        incidentRepo.save(incCrit);

        List<Incident> criticalOnly = incidentRepo.findBySeverity(ThreatLevel.CRITICAL);
        assertEquals(1, criticalOnly.size());
        assertEquals("inc-crit", criticalOnly.get(0).getId());
    }

    @Test
    public void testUpdateIncidentStatus() {
        Incident incident = new Incident(
                "inc-002", Instant.now(), ThreatLevel.HIGH, 72, "C:/Test", 30, 2, 7.1, 7.4, 12.0,
                "High threat", IncidentStatus.DETECTED, List.of()
        );
        incidentRepo.save(incident);

        boolean updated = incidentRepo.updateStatus("inc-002", IncidentStatus.ACKNOWLEDGED);
        assertTrue(updated);

        List<Incident> all = incidentRepo.findAll();
        assertEquals(IncidentStatus.ACKNOWLEDGED, all.get(0).getStatus());
    }

    @Test
    public void testSaveAndRetrieveFileEvents() {
        FileEvent event = new FileEvent(
                Paths.get("test-data/Documents/secret.txt"),
                "MODIFY",
                Instant.now(),
                4096,
                Paths.get("test-data/Documents")
        );
        event.setEntropy(7.82);

        fileEventRepo.save(event, "inc-001");

        List<FileEvent> recent = fileEventRepo.findRecent(10);
        assertEquals(1, recent.size());
        assertEquals("MODIFY", recent.get(0).getEventType());
        assertEquals(7.82, recent.get(0).getEntropy(), 0.01);
    }
}
