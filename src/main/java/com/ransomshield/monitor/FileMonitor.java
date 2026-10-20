package com.ransomshield.monitor;

import com.ransomshield.model.FileEvent;
import com.ransomshield.util.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

import static java.nio.file.StandardWatchEventKinds.*;

/**
 * Real-time filesystem monitor using Java NIO WatchService.
 * Recursively watches designated directories, dynamically registers newly created subdirectories,
 * and feeds events into the event queue.
 */
public class FileMonitor implements Runnable {
    private static final Logger logger = LoggerFactory.getLogger(FileMonitor.class);

    private final EventQueueManager eventQueue;
    private final boolean recursive;
    private final AtomicBoolean running = new AtomicBoolean(false);

    private WatchService watchService;
    private Thread monitorThread;
    private Path rootDirectory;
    private final Map<WatchKey, Path> keyToPathMap = new ConcurrentHashMap<>();
    private final Set<Path> registeredPaths = ConcurrentHashMap.newKeySet();

    // Rename correlation tracking
    private final Map<String, DeletedFileInfo> recentDeletes = new ConcurrentHashMap<>();
    private final Map<String, CreatedFileInfo> recentCreates = new ConcurrentHashMap<>();

    private static class DeletedFileInfo {
        final Path originalPath;
        final Instant timestamp;

        DeletedFileInfo(Path originalPath, Instant timestamp) {
            this.originalPath = originalPath;
            this.timestamp = timestamp;
        }
    }

    private static class CreatedFileInfo {
        final Path path;
        final Instant timestamp;

        CreatedFileInfo(Path path, Instant timestamp) {
            this.path = path;
            this.timestamp = timestamp;
        }
    }

    public FileMonitor(EventQueueManager eventQueue, boolean recursive) {
        this.eventQueue = eventQueue;
        this.recursive = recursive;
    }

    /**
     * Starts monitoring the registered paths in a dedicated background thread.
     */
    public synchronized void startMonitoring(Path rootDirectory) throws IOException {
        if (running.get()) {
            logger.warn("FileMonitor is already running");
            return;
        }

        if (rootDirectory == null || !Files.exists(rootDirectory)) {
            throw new IllegalArgumentException("Root directory must exist: " + rootDirectory);
        }

        this.rootDirectory = rootDirectory.toAbsolutePath().normalize();
        this.watchService = FileSystems.getDefault().newWatchService();
        keyToPathMap.clear();
        registeredPaths.clear();

        if (recursive) {
            registerRecursive(this.rootDirectory);
        } else {
            registerDirectory(this.rootDirectory);
        }

        running.set(true);
        monitorThread = new Thread(this, "RansomShield-WatchService-Thread");
        monitorThread.setDaemon(true);
        monitorThread.start();

        logger.info("Started FileMonitor on {} (recursive={})", this.rootDirectory, recursive);
    }

    /**
     * Stops the monitoring thread and closes the WatchService.
     */
    public synchronized void stopMonitoring() {
        if (!running.get()) return;

        running.set(false);
        try {
            if (watchService != null) {
                watchService.close();
            }
        } catch (IOException e) {
            logger.debug("Error closing watch service: {}", e.getMessage());
        }

        if (monitorThread != null) {
            monitorThread.interrupt();
            try {
                monitorThread.join(1000);
            } catch (InterruptedException ignored) {}
        }

        keyToPathMap.clear();
        registeredPaths.clear();
        recentDeletes.clear();
        recentCreates.clear();
        logger.info("Stopped FileMonitor");
    }

    public boolean isRunning() {
        return running.get();
    }

    /**
     * Recursively registers a directory tree with the WatchService.
     */
    public void registerRecursive(Path root) throws IOException {
        Files.walkFileTree(root, new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                try {
                    registerDirectory(dir);
                } catch (IOException e) {
                    logger.warn("Failed to register directory {}: {}", dir, e.getMessage());
                }
                return FileVisitResult.CONTINUE;
            }
        });
    }

    /**
     * Registers a single directory with the WatchService.
     */
    public synchronized void registerDirectory(Path dir) throws IOException {
        Path normalized = dir.toAbsolutePath().normalize();
        if (registeredPaths.contains(normalized)) {
            return;
        }

        WatchKey key = normalized.register(
                watchService,
                ENTRY_CREATE,
                ENTRY_MODIFY,
                ENTRY_DELETE
        );

        keyToPathMap.put(key, normalized);
        registeredPaths.add(normalized);
        logger.debug("Registered watch directory: {}", normalized);
    }

    @Override
    public void run() {
        logger.info("WatchService event loop running");

        while (running.get()) {
            WatchKey key;
            try {
                key = watchService.take();
            } catch (InterruptedException | ClosedWatchServiceException e) {
                break;
            }

            Path dir = keyToPathMap.get(key);
            if (dir == null) {
                key.reset();
                continue;
            }

            List<WatchEvent<?>> events = new ArrayList<>(key.pollEvents());
            // Prioritize DELETE before CREATE so rename correlation can match deletes populated in same batch
            events.sort((e1, e2) -> {
                if (e1.kind() == ENTRY_DELETE && e2.kind() != ENTRY_DELETE) return -1;
                if (e1.kind() != ENTRY_DELETE && e2.kind() == ENTRY_DELETE) return 1;
                return 0;
            });

            for (WatchEvent<?> event : events) {
                WatchEvent.Kind<?> kind = event.kind();

                if (kind == OVERFLOW) {
                    logger.warn("WatchService OVERFLOW detected in directory {}", dir);
                    continue;
                }

                @SuppressWarnings("unchecked")
                WatchEvent<Path> ev = (WatchEvent<Path>) event;
                Path filename = ev.context();
                Path child = dir.resolve(filename);
                Path normalizedChild = child.toAbsolutePath().normalize();

                Instant now = Instant.now();
                String eventType;
                Path oldPath = null;

                // Prune tracking older than 4 seconds
                Instant cutoff = now.minusSeconds(4);
                recentDeletes.entrySet().removeIf(entry -> entry.getValue().timestamp.isBefore(cutoff));
                recentCreates.entrySet().removeIf(entry -> entry.getValue().timestamp.isBefore(cutoff));

                if (kind == ENTRY_CREATE) {
                    // Dynamically register newly created subdirectories
                    if (Files.isDirectory(child, LinkOption.NOFOLLOW_LINKS)) {
                        if (recursive) {
                            try {
                                registerRecursive(child);
                            } catch (IOException e) {
                                logger.warn("Could not register new subdirectory {}: {}", child, e.getMessage());
                            }
                        }
                        continue; // Do not emit file events for directories
                    }

                    eventType = "CREATE";

                    // Check for rename correlation from recent delete in same directory:
                    // 1. Direct stripped extension: file.txt.encrypted -> file.txt
                    String cand1 = dir.toAbsolutePath().normalize() + "/" + stripLastExtension(filename.toString());
                    // 2. Base name without any extension: file.txt.encrypted -> file
                    String cand2 = dir.toAbsolutePath().normalize() + "/" + getRootBaseName(filename.toString());

                    DeletedFileInfo match = recentDeletes.remove(cand1);
                    if (match == null) match = recentDeletes.remove(cand2);

                    if (match != null && !normalizedChild.equals(match.originalPath.toAbsolutePath().normalize())) {
                        eventType = "RENAME";
                        oldPath = match.originalPath;
                    } else {
                        // Record this create in case the delete event arrives slightly later
                        recentCreates.put(cand1, new CreatedFileInfo(child, now));
                        recentCreates.put(cand2, new CreatedFileInfo(child, now));
                    }

                } else if (kind == ENTRY_MODIFY) {
                    if (Files.isDirectory(child, LinkOption.NOFOLLOW_LINKS)) {
                        continue; // Do not emit file events for directories
                    }
                    eventType = "MODIFY";

                } else if (kind == ENTRY_DELETE) {
                    // If a watched directory itself is deleted, do not emit file event
                    if (registeredPaths.contains(normalizedChild)) {
                        continue;
                    }

                    // Check if this delete corresponds to a create that arrived milliseconds earlier (reverse rename)
                    String cand1 = dir.toAbsolutePath().normalize() + "/" + filename.toString();
                    String cand2 = dir.toAbsolutePath().normalize() + "/" + stripLastExtension(filename.toString());

                    CreatedFileInfo createMatch = recentCreates.remove(cand1);
                    if (createMatch == null) createMatch = recentCreates.remove(cand2);

                    if (createMatch != null && !normalizedChild.equals(createMatch.path.toAbsolutePath().normalize())) {
                        // The file creation was already recorded; this delete is the old file half of the rename
                        continue;
                    }

                    eventType = "DELETE";
                    DeletedFileInfo delInfo = new DeletedFileInfo(child, now);
                    recentDeletes.put(cand1, delInfo);
                    recentDeletes.put(cand2, delInfo);

                } else {
                    eventType = kind.name();
                }

                long fileSize = FileUtils.getFileSizeSafely(child);
                FileEvent fileEvent = new FileEvent(child, eventType, now, fileSize, dir, oldPath);

                // Non-blocking handoff to analysis queue
                eventQueue.offer(fileEvent);
            }

            boolean valid = key.reset();
            if (!valid) {
                keyToPathMap.remove(key);
                registeredPaths.remove(dir);
                if (keyToPathMap.isEmpty()) {
                    // Attempt self-healing re-registration if rootDirectory still exists
                    if (running.get() && rootDirectory != null && Files.exists(rootDirectory)) {
                        logger.info("Watched directory keys lost; re-registering root: {}", rootDirectory);
                        try {
                            if (recursive) {
                                registerRecursive(rootDirectory);
                            } else {
                                registerDirectory(rootDirectory);
                            }
                        } catch (IOException e) {
                            logger.warn("Failed to re-register root directory: {}", e.getMessage());
                        }
                    } else {
                        logger.info("All watched directories are no longer accessible");
                        break;
                    }
                }
            }
        }

        logger.info("WatchService event loop exited");
    }

    private String stripLastExtension(String filename) {
        int dot = filename.lastIndexOf('.');
        return (dot > 0) ? filename.substring(0, dot) : filename;
    }

    private String getRootBaseName(String filename) {
        int dot = filename.indexOf('.');
        return (dot > 0) ? filename.substring(0, dot) : filename;
    }

    public Set<Path> getRegisteredPaths() {
        return Collections.unmodifiableSet(registeredPaths);
    }
}
