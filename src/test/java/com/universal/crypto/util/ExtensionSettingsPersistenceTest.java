package com.universal.crypto.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.util.concurrent.TimeUnit;
import static org.junit.jupiter.api.Assertions.*;

class ExtensionSettingsPersistenceTest {
    @TempDir Path home;

    @Test void stagedSaveReplacesWholeFileAndLeavesNoTemporaryFile() throws Exception { probe("success"); }
    @Test void persistenceFailurePropagatesAndRetainsExistingFile() throws Exception { probe("failure"); }

    private void probe(String scenario) throws Exception {
        Process process=new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin","java").toString(),
                "-Duser.home="+home,"-cp",System.getProperty("java.class.path"),Probe.class.getName(),scenario)
                .redirectErrorStream(true).start();
        assertTrue(process.waitFor(10,TimeUnit.SECONDS));
        String output=new String(process.getInputStream().readAllBytes(),java.nio.charset.StandardCharsets.UTF_8);
        assertEquals(0,process.exitValue(),output);assertTrue(output.contains("PASS"),output);
    }

    public static class Probe {
        public static void main(String[] args) throws Exception {
            Path directory=Path.of(System.getProperty("user.home"),".burp","universal-crypto-extension");
            ExtensionSettings staged=new ObjectMapper().readValue("{}",ExtensionSettings.class);
            if ("failure".equals(args[0])) {
                Files.createDirectories(directory.getParent());Files.writeString(directory,"existing-file");
                try {staged.saveOrThrow();throw new AssertionError("save must throw");}
                catch(java.io.IOException expected) {
                    if(!"existing-file".equals(Files.readString(directory)))throw new AssertionError("existing path was changed");
                }
            } else {
                staged.setApiBaseUrl("https://first.example/api");staged.saveOrThrow();
                staged.setApiBaseUrl("https://second.example/api");staged.saveOrThrow();
                ExtensionSettings stored=new ObjectMapper().readValue(directory.resolve("config.json").toFile(),ExtensionSettings.class);
                if(!"https://second.example/api".equals(stored.getApiBaseUrl()))throw new AssertionError("partial configuration");
                try(var files=Files.list(directory)) {if(files.count()!=1)throw new AssertionError("leaked staged file");}
                if(!"http://localhost:8080/api".equals(ExtensionSettings.getInstance().getApiBaseUrl()))throw new AssertionError("live settings changed before publish");
            }
            System.out.println("PASS");
        }
    }
}
