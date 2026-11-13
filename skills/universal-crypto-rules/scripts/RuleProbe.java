import com.fasterxml.jackson.databind.*;
import com.universal.crypto.engine.*;
import com.universal.crypto.handler.*;
import com.universal.crypto.model.*;
import com.universal.crypto.processor.*;
import com.universal.crypto.util.Logger;
import java.nio.file.*;
import java.net.URL;
import java.util.*;

/** Uses the real plugin import, processors, match engine, wire interceptor and phase service. */
@SuppressWarnings("deprecation")
public class RuleProbe {
    private static final ObjectMapper JSON = RuleSerializer.getObjectMapper();
    private static final Set<String> RULE_FIELDS = Set.of("id","name","category","enabled","priority","description","condition","requestActions","responseActions","showInEditor","requestActionCount","responseActionCount");
    private static final Set<String> CONDITION_FIELDS = Set.of("hosts","paths","methods","headers","contentPattern","toolSource","contentType");
    private static final Set<String> ACTION_FIELDS = Set.of("actionType","targetType","targetName","processor","config","enabled","description");
    private static void require(boolean value, String message) { if (!value) throw new IllegalArgumentException(message); }
    private static void fields(JsonNode node, Set<String> allowed, String label) {
        require(node.isObject(), label + " must be an object");
        node.fieldNames().forEachRemaining(k -> require(allowed.contains(k), "Unknown " + label + " field: " + k));
    }
    private static Map<String,String> headers(JsonNode node) {
        Map<String,String> result = new LinkedHashMap<>();
        if (node != null) node.fields().forEachRemaining(e -> result.put(e.getKey(), e.getValue().asText()));
        return result;
    }
    private static void expect(JsonNode fixture, Map<String,Object> actual) {
        JsonNode expected = fixture.get("expect");
        require(expected != null && expected.isObject() && !expected.isEmpty(), "Each case requires nonempty expect");
        JsonNode output = JSON.valueToTree(actual);
        expected.fields().forEachRemaining(e -> {
            String key=e.getKey();
            require(Set.of("body","bodyBase64","headers","matched","success","errors","unchanged").contains(key), "Unknown expectation: " + key);
            if (key.equals("headers")) {
                Map<String,String> got = headers(output.path("headers"));
                e.getValue().fields().forEachRemaining(h -> {
                    String value = got.entrySet().stream().filter(x -> x.getKey().equalsIgnoreCase(h.getKey())).map(Map.Entry::getValue).findFirst().orElse(null);
                    require(Objects.equals(value, h.getValue().asText()), "Header expectation failed: " + h.getKey());
                });
            } else require(Objects.equals(output.get(key),e.getValue()), "Expectation failed: " + key);
        });
    }
    public static void main(String[] args) throws Exception {
        Logger.getInstance().initialize("ERROR", false, false, ".");
        String raw=Files.readString(Path.of(args[0]));
        JsonNode root=JSON.readTree(raw);
        JsonNode rulesNode=root.isArray()?root:root.path("rules");
        require(rulesNode.isArray(), "File must contain a rule array or versioned envelope");
        if (root.isObject()) fields(root,Set.of("schemaVersion","engineBuild","rules"),"envelope");
        Set<String> configKeys=new HashSet<>();
        for (java.lang.reflect.Field f : Constants.ConfigKey.class.getFields()) if(f.getType()==String.class) configKeys.add((String)f.get(null));
        for(JsonNode r:rulesNode) {
            fields(r,RULE_FIELDS,"rule");
            require(r.has("condition") && !r.get("condition").isNull(),"condition must be explicit; null never matches");
            fields(r.get("condition"),CONDITION_FIELDS,"condition");
            for(String direction:List.of("requestActions","responseActions")) {
                if(!r.has(direction)) continue;
                require(r.get(direction).isArray(),direction+" must be an array");
                for(JsonNode a:r.get(direction)) {
                    fields(a,ACTION_FIELDS,"action");
                    if(a.has("config")) fields(a.get("config"),configKeys,"config");
                }
            }
        }
        List<ProcessingRule> rules=RuleSerializer.importRules(raw); // syntax, enums, version, disabled import semantics
        require(!rules.isEmpty(),"No rules found");
        ProcessorManager processors=ProcessorFactory.createDefaultProcessorManager(null); // REAL internal engines; no mock/external client
        boolean external=false;
        int actionCount=0;
        for(ProcessingRule r:rules) {
            require(r.hasActions(),"Rule has no actions: "+r.getId());
            List<ProcessingAction> actions=new ArrayList<>(r.getRequestActions()); actions.addAll(r.getResponseActions());
            for(ProcessingAction a:actions) {
                actionCount++;
                ProcessorInterface processor=processors.getProcessor(a.getProcessor());
                require(processor!=null && processor.validateConfiguration(a),"Invalid action configuration: "+r.getId()+":"+a.getActionType());
                if(Set.of("header","variable").contains(a.getTargetType())) require(a.getTargetName()!=null || (a.getTargetType().equals("variable") && a.getConfigString("variableName")!=null),"Missing targetName/variableName");
                if(Set.of("crypto","signature").contains(a.getProcessor())) {
                    external |= !"internal".equalsIgnoreCase(a.getConfigString("cryptoProvider"));
                    external |= "lookup".equalsIgnoreCase(a.getConfigString("keySource")) || Boolean.parseBoolean(a.getConfigString("fallbackLookup"));
                }
            }
            r.setEnabled(true); // isolated simulation only; imported persisted rules remain disabled
        }
        Map<String,Object> report=new LinkedHashMap<>();
        report.put("runtime",System.getProperty("uce.probe.runtime", "unspecified"));
        report.put("javaVersion",System.getProperty("java.version"));
        report.put("engineBuild",RuleSerializer.ENGINE_BUILD);
        report.put("valid",true); report.put("rules",rules.size()); report.put("actions",actionCount);
        report.put("externalExecutionRequired",external);
        if(args.length==1) { System.out.println(JSON.writeValueAsString(report)); return; }
        require(!external,"Fixture execution rejects external/lookup paths; structure was validated, no network was accessed");
        Path temp=Path.of(args[2]);
        RuleManager manager=new RuleManager(new RuleConfigStorage(temp.toString())); manager.setRules(rules);
        RuleMatchEngine matchEngine=new RuleMatchEngine();
        HttpInterceptor interceptor=new HttpInterceptor(manager,matchEngine,processors);
        RuleProcessingService service=new RuleProcessingService(manager,matchEngine,processors);
        List<String> actionErrors=new ArrayList<>();
        interceptor.addTrafficListener((m,u,status,info,before,after)->{ if(status.contains("Failed") || status.equals("Processing Error")) actionErrors.add(status+":"+info); });
        JsonNode fixtures=JSON.readTree(Files.readString(Path.of(args[1])));
        require(fixtures.path("cases").isArray() && !fixtures.path("cases").isEmpty(),"Fixture file requires nonempty cases array");
        List<Map<String,Object>> results=new ArrayList<>();
        for(JsonNode fixture:fixtures.path("cases")) {
            actionErrors.clear();
            fields(fixture,Set.of("name","direction","route","method","url","headers","requestHeaders","body","bodyBase64","messageId","toolSource","expect"),"fixture");
            String direction=fixture.path("direction").asText("request");
            require(Set.of("request","response").contains(direction),"Unknown direction");
            String route=fixture.path("route").asText("wire");
            require((direction.equals("request")?Set.of("wire","display","editor-send"):Set.of("wire","response-display","response-editor-send")).contains(route),"Unknown/inapplicable route");
            String toolSource=fixture.path("toolSource").asText("REPEATER");
            String method=fixture.path("method").asText("POST"); URL url=new URL(fixture.path("url").asText());
            Map<String,String> h=headers(fixture.get("headers"));
            Integer id=fixture.has("messageId")?fixture.get("messageId").asInt():null;
            require(!(fixture.has("body") && fixture.has("bodyBase64")),"Choose body or bodyBase64");
            HttpContextBase before;
            if(direction.equals("request")) {
                HttpRequestContext.Builder b=HttpRequestContext.builder().method(method).url(url).headers(h).toolSource(toolSource).messageId(id);
                if(fixture.has("bodyBase64")) b.bodyBytes(Base64.getDecoder().decode(fixture.get("bodyBase64").asText())); else b.body(fixture.path("body").asText(""));
                before=b.build();
            } else {
                HttpResponseContext.Builder b=HttpResponseContext.builder().method(method).url(url).headers(h).requestHeaders(fixture.has("requestHeaders") ? headers(fixture.get("requestHeaders")) : null).toolSource(toolSource).messageId(id).statusCode(200);
                if(fixture.has("bodyBase64")) b.bodyBytes(Base64.getDecoder().decode(fixture.get("bodyBase64").asText())); else b.body(fixture.path("body").asText(""));
                before=b.build();
            }
            RuleMatchEngine.MatchContext mc=direction.equals("request")?RuleMatchEngine.createRequestContext(method,url,h,before.getBody(),toolSource):RuleMatchEngine.createResponseContext(method,url,h,before.getBody(),toolSource);
            boolean matched=!matchEngine.findMatchingRules(manager.getEnabledRulesByPriority(),mc).isEmpty();
            Map<String,Object> actual=new LinkedHashMap<>(); actual.put("name",fixture.path("name").asText("case")); actual.put("matched",matched);
            if(route.equals("wire")) {
                HttpContextBase after=direction.equals("request")?interceptor.processRequest((HttpRequestContext)before):interceptor.processResponse((HttpResponseContext)before);
                actual.put("body",after.getBody()); actual.put("bodyBase64",Base64.getEncoder().encodeToString(after.getBodyBytes())); actual.put("headers",after.getHeaders());
                actual.put("success",!after.hasError() && actionErrors.isEmpty()); actual.put("errors",actionErrors.size()+(after.hasError()?1:0));
                if(!actionErrors.isEmpty()) actual.put("errorDetails",new ArrayList<>(actionErrors));
                if(after.hasError()) actual.put("error",after.getErrorMessage());
                actual.put("unchanged",Arrays.equals(before.getBodyBytes(),after.getBodyBytes()) && before.getHeaders().equals(after.getHeaders()));
            } else {
                RuleProcessingService.ProcessingOutcome outcome=direction.equals("request")?service.processRequestForPhase((HttpRequestContext)before,before.getBody(),route):service.processResponseForPhase((HttpResponseContext)before,before.getBody(),route);
                actual.put("matched",outcome.isMatched()); actual.put("success",outcome.isSuccess()); actual.put("errors",outcome.isSuccess()?0:1);
                if(!outcome.isSuccess()) actual.put("error",outcome.getError());
                actual.put("body",outcome.getContent()); actual.put("headers",outcome.getModifiedHeaders()==null?Map.of():outcome.getModifiedHeaders());
                actual.put("unchanged",Objects.equals(before.getBody(),outcome.getContent()) && (outcome.getModifiedHeaders()==null || outcome.getModifiedHeaders().isEmpty()));
            }
            try { expect(fixture,actual); } catch (IllegalArgumentException e) {
                System.err.println(JSON.writeValueAsString(Map.of("case",actual.get("name"),"actual",actual,"failure",e.getMessage())));
                throw e;
            }
            results.add(actual);
        }
        report.put("casesPassed",results.size()); report.put("results",results);
        System.out.println(JSON.writeValueAsString(report));
    }
}
