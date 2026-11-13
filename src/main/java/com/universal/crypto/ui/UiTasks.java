package com.universal.crypto.ui;

import javax.swing.SwingWorker;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;

/** Runs captured input off the EDT and publishes the result on the EDT. */
final class UiTasks {
    private UiTasks() {}

    static <T> SwingWorker<T, Void> start(Callable<T> task, Consumer<T> success,
                                        Consumer<Exception> failure, Runnable finished) {
        SwingWorker<T, Void> worker = new SwingWorker<>() {
            @Override protected T doInBackground() throws Exception { return task.call(); }
            @Override protected void done() {
                try {
                    if (!isCancelled()) success.accept(get());
                } catch (CancellationException ignored) {
                } catch (Exception ex) {
                    Throwable cause = ex instanceof ExecutionException ? ex.getCause() : ex;
                    failure.accept(cause instanceof Exception e ? e : new RuntimeException(cause));
                } finally {
                    finished.run();
                }
            }
        };
        worker.execute();
        return worker;
    }
}
