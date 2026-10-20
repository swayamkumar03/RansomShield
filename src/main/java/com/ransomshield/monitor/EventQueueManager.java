package com.ransomshield.monitor;

import com.ransomshield.model.FileEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Manages the high-performance bounded event queue decoupling fast filesystem
 * collection from downstream entropy and behavioral analysis workers.
 */
public class EventQueueManager {
    private static final Logger logger = LoggerFactory.getLogger(EventQueueManager.class);

    private final BlockingQueue<FileEvent> queue;
    private final AtomicLong totalEnqueued = new AtomicLong(0);
    private final AtomicLong totalDequeued = new AtomicLong(0);
    private final AtomicLong droppedEvents = new AtomicLong(0);

    public EventQueueManager(int capacity) {
        this.queue = new ArrayBlockingQueue<>(capacity > 0 ? capacity : 5000);
    }

    /**
     * Enqueues an event non-blockingly. If the queue is saturated during massive bursts,
     * tracks the dropped count rather than stalling the filesystem monitor thread.
     */
    public boolean offer(FileEvent event) {
        if (event == null) return false;

        boolean added = queue.offer(event);
        if (added) {
            totalEnqueued.incrementAndGet();
        } else {
            droppedEvents.incrementAndGet();
            logger.warn("Event queue full (size={})! Dropped event for {}", queue.size(), event.getPath());
        }
        return added;
    }

    /**
     * Retrieves and removes an event from the queue, waiting if necessary up to the specified timeout.
     */
    public FileEvent poll(long timeout, TimeUnit unit) throws InterruptedException {
        FileEvent event = queue.poll(timeout, unit);
        if (event != null) {
            totalDequeued.incrementAndGet();
        }
        return event;
    }

    public int size() {
        return queue.size();
    }

    public int remainingCapacity() {
        return queue.remainingCapacity();
    }

    public long getTotalEnqueued() {
        return totalEnqueued.get();
    }

    public long getTotalDequeued() {
        return totalDequeued.get();
    }

    public long getDroppedEvents() {
        return droppedEvents.get();
    }

    public void clear() {
        queue.clear();
    }
}
