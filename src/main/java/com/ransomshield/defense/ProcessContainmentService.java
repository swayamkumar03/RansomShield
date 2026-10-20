package com.ransomshield.defense;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * Interface and guarded implementation for process containment.
 * <p>
 * IMPORTANT PLATFORM LIMITATION:
 * Standard Java NIO {@link java.nio.file.WatchService} relies on OS filesystem notifications
 * (e.g., ReadDirectoryChangesW on Windows, inotify on Linux) which DO NOT deliver the Process ID (PID)
 * or executable path that triggered the I/O. Without kernel-level filter drivers (e.g. Minifilter / ETW on Windows
 * or auditd / eBPF on Linux), attributing a filesystem event directly to a process is not reliably possible.
 * RansomShield strictly avoids guessing PIDs from file extensions or filenames.
 * </p>
 */
public class ProcessContainmentService {
    private static final Logger logger = LoggerFactory.getLogger(ProcessContainmentService.class);

    // Protected critical processes that must NEVER be terminated
    private static final Set<String> PROTECTED_PROCESS_NAMES = Set.of(
            "system", "system idle process", "registry", "smss.exe", "csrss.exe",
            "wininit.exe", "services.exe", "lsass.exe", "svchost.exe", "explorer.exe",
            "winlogon.exe", "dwm.exe", "spoolsv.exe", "taskmgr.exe"
    );

    private static final Set<Long> PROTECTED_PIDS = Set.of(0L, 4L);

    /**
     * Attempts or simulates process containment for a specified process ID.
     *
     * @param pid Target Process ID
     * @param simulate If true, executes safely in simulation mode without terminating
     * @return ResponseResult detailing outcome
     */
    public ResponseResult containProcess(long pid, boolean simulate) {
        long currentJvmPid = ProcessHandle.current().pid();

        // 1. Never terminate the RansomShield JVM itself
        if (pid == currentJvmPid) {
            return ResponseResult.failure(ResponseAction.TERMINATE_PROCESS,
                    "Target validation rejected: target is the RansomShield JVM itself (PID " + pid + ")",
                    "Self-termination guard");
        }

        // 2. Never terminate protected system PIDs
        if (PROTECTED_PIDS.contains(pid)) {
            return ResponseResult.failure(ResponseAction.TERMINATE_PROCESS,
                    "Target validation rejected: PID " + pid + " is a protected OS core kernel process",
                    "Protected kernel PID");
        }

        Optional<ProcessHandle> processOpt = ProcessHandle.of(pid);
        if (processOpt.isEmpty()) {
            return ResponseResult.failure(ResponseAction.TERMINATE_PROCESS,
                    "Process PID " + pid + " not found or already exited",
                    "Process not alive");
        }

        ProcessHandle handle = processOpt.get();
        String command = handle.info().command().orElse("unknown");
        String processName = getProcessBasename(command);

        // 3. Check protected system names
        if (PROTECTED_PROCESS_NAMES.contains(processName.toLowerCase(Locale.ROOT))) {
            return ResponseResult.failure(ResponseAction.TERMINATE_PROCESS,
                    "Target validation rejected: '" + processName + "' (PID " + pid + ") is a critical OS service",
                    "Protected system process");
        }

        if (simulate) {
            String simMsg = String.format("SIMULATED: Identified eligible candidate process '%s' (PID %d). " +
                    "Termination simulated safely in audit log. No process was modified.", processName, pid);
            logger.info("Process containment simulation: PID {}", pid);
            return ResponseResult.successSimulated(ResponseAction.TERMINATE_PROCESS, simMsg, List.of("PID: " + pid + " (" + processName + ")"));
        }

        // 4. Real containment (Guarded execution)
        try {
            boolean destroyed = handle.destroy();
            if (destroyed) {
                // Verify termination
                try {
                    Thread.sleep(100);
                } catch (InterruptedException ignored) {}

                boolean stillAlive = handle.isAlive();
                if (stillAlive) {
                    handle.destroyForcibly();
                }

                String successMsg = String.format("Terminated verified candidate process '%s' (PID %d)", processName, pid);
                logger.warn("REAL CONTAINMENT: Process terminated: {} (PID {})", processName, pid);
                return ResponseResult.successReal(ResponseAction.TERMINATE_PROCESS, successMsg, List.of("PID: " + pid + " (" + processName + ")"));
            } else {
                return ResponseResult.failure(ResponseAction.TERMINATE_PROCESS,
                        "Failed to signal termination to PID " + pid + ". Permission denied or process elevated.",
                        "AccessDenied");
            }
        } catch (SecurityException e) {
            return ResponseResult.failure(ResponseAction.TERMINATE_PROCESS,
                    "SecurityException terminating PID " + pid + ": " + e.getMessage(), e.getMessage());
        } catch (Exception e) {
            return ResponseResult.failure(ResponseAction.TERMINATE_PROCESS,
                    "Unexpected error terminating PID " + pid + ": " + e.getMessage(), e.getMessage());
        }
    }

    private String getProcessBasename(String fullPath) {
        if (fullPath == null || fullPath.isBlank()) return "unknown";
        int lastSlash = Math.max(fullPath.lastIndexOf('/'), fullPath.lastIndexOf('\\'));
        return lastSlash >= 0 ? fullPath.substring(lastSlash + 1) : fullPath;
    }
}
