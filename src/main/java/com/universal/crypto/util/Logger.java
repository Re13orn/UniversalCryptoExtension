package com.universal.crypto.util;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Centralized logging utility for Universal Crypto Extension
 * Provides thread-safe logging with configurable output destinations
 */
public class Logger {

    /**
     * Log levels
     */
    public static final class LogLevel {
        public static final String DEBUG = "DEBUG";
        public static final String INFO = "INFO";
        public static final String WARN = "WARN";
        public static final String ERROR = "ERROR";

        private LogLevel() {}
    }

    private static final ThreadLocal<SimpleDateFormat> TIMESTAMP_FORMAT = ThreadLocal.withInitial(() -> new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS"));
    private static final String LOG_FILE_NAME = "universal-crypto-extension.log";
    private static final int MAX_LOG_ENTRIES = 1000;

    private static volatile Logger instance;
    private static final Object LOCK = new Object();

    private final ConcurrentLinkedQueue<String> logBuffer = new ConcurrentLinkedQueue<>();
    private final AtomicBoolean initialized = new AtomicBoolean(false);

    private volatile String currentLogLevel = LogLevel.INFO;
    private volatile boolean logToConsole = true;
    private volatile boolean logToFile = false;
    private volatile String logDirectory;
    private volatile PrintWriter fileWriter;

    private Logger() {
        // Private constructor for singleton
    }

    public static Logger getInstance() {
        if (instance == null) {
            synchronized (LOCK) {
                if (instance == null) {
                    instance = new Logger();
                }
            }
        }
        return instance;
    }

    /**
     * Initialize logger with configuration
     */
    public void initialize(String logLevel, boolean logToConsole, boolean logToFile, String logDirectory) {
        // Allow re-initialization to update settings
        if (initialized.get()) {
            // Update settings but don't prevent execution
            this.currentLogLevel = logLevel != null ? logLevel : LogLevel.INFO;
            this.logToConsole = logToConsole;
            this.logToFile = logToFile;
            this.logDirectory = logDirectory;
            if (logToFile) {
                 initializeFileLogging(); // Re-init file logging if paths changed
            }
            info("Logger configuration updated");
            return;
        }
        initialized.set(true);

        this.currentLogLevel = logLevel != null ? logLevel : LogLevel.INFO;
        this.logToConsole = logToConsole;
        this.logToFile = logToFile;
        this.logDirectory = logDirectory;

        // Null safety for logDirectory if logToFile is requested
        if (logToFile && (logDirectory == null || logDirectory.trim().isEmpty())) {
            warn("Log to file requested but directory is empty. Disabling file logging.");
            this.logToFile = false;
        }

        if (this.logToFile) {
            initializeFileLogging();
        }

        info("Logger initialized - Level: " + this.currentLogLevel +
             ", Console: " + this.logToConsole + ", File: " + this.logToFile);
    }

    private void initializeFileLogging() {
        // Close existing writer if open to prevent leaks
        if (fileWriter != null) {
            synchronized (fileWriter) {
                fileWriter.flush();
                fileWriter.close();
                fileWriter = null;
            }
        }

        try {
            if (logDirectory == null) return;
            
            File logDir = new File(logDirectory);
            if (!logDir.exists() && !logDir.mkdirs()) {
                error("Failed to create log directory: " + logDirectory);
                this.logToFile = false; // Disable if we can't create dir
                return;
            }

            File logFile = new File(logDir, LOG_FILE_NAME);
            fileWriter = new PrintWriter(new FileWriter(logFile, true));

        } catch (IOException e) {
            error("Failed to initialize file logging: " + e.getMessage());
            this.logToFile = false; // Disable on error
        }
    }

    public void debug(String message) {
        log(LogLevel.DEBUG, message, null);
    }

    public void debug(String message, Throwable throwable) {
        log(LogLevel.DEBUG, message, throwable);
    }

    public void info(String message) {
        log(LogLevel.INFO, message, null);
    }

    public void info(String message, Throwable throwable) {
        log(LogLevel.INFO, message, throwable);
    }

    public void warn(String message) {
        log(LogLevel.WARN, message, null);
    }

    public void warn(String message, Throwable throwable) {
        log(LogLevel.WARN, message, throwable);
    }

    public void error(String message) {
        log(LogLevel.ERROR, message, null);
    }

    public void error(String message, Throwable throwable) {
        log(LogLevel.ERROR, message, throwable);
    }

    private void log(String level, String message, Throwable throwable) {
        if (!shouldLog(level)) {
            return;
        }

        String timestamp = TIMESTAMP_FORMAT.get().format(new Date());
        String threadName = Thread.currentThread().getName();

        StringBuilder logEntry = new StringBuilder();
        logEntry.append("[").append(timestamp).append("]");
        logEntry.append(" [").append(level).append("]");
        logEntry.append(" [").append(threadName).append("]");
        logEntry.append(" ").append(message);

        if (throwable != null) {
            logEntry.append("\n").append(getStackTrace(throwable));
        }

        String formattedLog = logEntry.toString();

        // Add to buffer for debugging
        addToBuffer(formattedLog);

        // Output to destinations
        if (logToConsole) {
            System.out.println(formattedLog);
        }

        if (logToFile && fileWriter != null) {
            synchronized (fileWriter) {
                fileWriter.println(formattedLog);
                fileWriter.flush();
            }
        }
    }

    private boolean shouldLog(String level) {
        return getLogLevelPriority(level) >= getLogLevelPriority(currentLogLevel);
    }

    private int getLogLevelPriority(String level) {
        switch (level) {
            case LogLevel.DEBUG: return 1;
            case LogLevel.INFO: return 2;
            case LogLevel.WARN: return 3;
            case LogLevel.ERROR: return 4;
            default: return 0;
        }
    }

    private void addToBuffer(String logEntry) {
        logBuffer.offer(logEntry);

        // Maintain buffer size
        while (logBuffer.size() > MAX_LOG_ENTRIES) {
            logBuffer.poll();
        }
    }

    private String getStackTrace(Throwable throwable) {
        StringBuilder sb = new StringBuilder();
        sb.append(throwable.getClass().getName()).append(": ").append(throwable.getMessage());

        for (StackTraceElement element : throwable.getStackTrace()) {
            sb.append("\n\tat ").append(element.toString());
        }

        Throwable cause = throwable.getCause();
        if (cause != null) {
            sb.append("\nCaused by: ").append(getStackTrace(cause));
        }

        return sb.toString();
    }

    /**
     * Get recent log entries for debugging
     */
    public String[] getRecentLogs(int count) {
        int size = Math.min(count, logBuffer.size());
        String[] logs = new String[size];

        int index = 0;
        for (String log : logBuffer) {
            if (index >= size) break;
            logs[index++] = log;
        }

        return logs;
    }

    /**
     * Update log level at runtime
     */
    public void setLogLevel(String logLevel) {
        this.currentLogLevel = logLevel;
        info("Log level changed to: " + logLevel);
    }

    /**
     * Get current log level
     */
    public String getLogLevel() {
        return currentLogLevel;
    }

    /**
     * Check if debug logging is enabled
     */
    public boolean isDebugEnabled() {
        return shouldLog(LogLevel.DEBUG);
    }

    /**
     * Shutdown logger and clean up resources
     */
    public void shutdown() {
        info("Logger shutting down");

        if (fileWriter != null) {
            synchronized (fileWriter) {
                fileWriter.close();
                fileWriter = null;
            }
        }

        logBuffer.clear();
        initialized.set(false);
    }
}