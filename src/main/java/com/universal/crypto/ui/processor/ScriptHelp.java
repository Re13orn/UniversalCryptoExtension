package com.universal.crypto.ui.processor;

import com.universal.crypto.util.LanguageManager;
import java.util.stream.IntStream;

/** Shared, localized runtime guidance for action editing and the Playground. */
public final class ScriptHelp {
    private ScriptHelp() { }
    public static String text(String name) { return LanguageManager.getInstance().getString("script.help." + name); }
    public static String[] topics() { return IntStream.range(0, 8).mapToObj(i -> text("topic." + i)).toArray(String[]::new); }
    public static String[] templates() { return IntStream.range(0, 7).mapToObj(i -> text("template." + i)).toArray(String[]::new); }
    public static String guide(int index) {
        String[] keys = {"first", "runtime", "http", "json", "write", "signature", "chain", "errors"};
        return text(keys[index < 0 || index >= keys.length ? 0 : index]);
    }
}
