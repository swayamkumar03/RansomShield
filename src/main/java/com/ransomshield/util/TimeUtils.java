package com.ransomshield.util;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/**
 * Consistent date and time formatting utilities for RansomShield.
 */
public class TimeUtils {
    private static final DateTimeFormatter TIME_FORMATTER = DateTimeFormatter.ofPattern("HH:mm:ss")
            .withZone(ZoneId.systemDefault());

    private static final DateTimeFormatter FULL_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
            .withZone(ZoneId.systemDefault());

    private TimeUtils() {}

    public static String formatTimeOnly(Instant instant) {
        if (instant == null) return "";
        return TIME_FORMATTER.format(instant);
    }

    public static String formatFull(Instant instant) {
        if (instant == null) return "";
        return FULL_FORMATTER.format(instant);
    }
}
