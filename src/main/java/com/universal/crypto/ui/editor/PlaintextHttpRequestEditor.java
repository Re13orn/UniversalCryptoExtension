package com.universal.crypto.ui.editor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import com.universal.crypto.engine.RuleProcessingService;
import com.universal.crypto.engine.RuleProcessingService.ProcessingOutcome;
import com.universal.crypto.handler.HttpRequestContext;
import com.universal.crypto.model.Constants;
import com.universal.crypto.burp.HttpContextMapper;

import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.Component;
import java.util.List;


/**
 * Custom HTTP request editor用于展示解密后的明文并在发送前重新加密。
 */
class PlaintextHttpRequestEditor implements ExtensionProvidedHttpRequestEditor {

    private final MontoyaApi api;
    private final RuleProcessingService processingService;
    private final EditorCreationContext creationContext;

    private final JPanel component;
    private final JTextArea textArea;
    private final PlaintextMessageView view;
    private final java.util.function.BiFunction<HttpService, String, HttpRequest> requestFactory;

    private HttpRequest currentRequest;
    private HttpRequest updatedRequest;
    private long preparedRevision;
    private boolean modified;
    private boolean hasMatch;
    private boolean editable;
    private String lastError;

    private String toolSourceName;

    PlaintextHttpRequestEditor(MontoyaApi api,
                               RuleProcessingService processingService,
                               EditorCreationContext creationContext) {
        this(api, processingService, creationContext, HttpRequest::httpRequest);
    }

    PlaintextHttpRequestEditor(MontoyaApi api, RuleProcessingService processingService,
                              EditorCreationContext creationContext,
                              java.util.function.BiFunction<HttpService, String, HttpRequest> requestFactory) {
        this.requestFactory = requestFactory;
        this.api = api;
        this.processingService = processingService;
        this.creationContext = creationContext;

        this.view = new PlaintextMessageView(api);
        this.textArea = view.textArea();
        this.textArea.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                markModified();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                markModified();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                markModified();
            }
        });

        this.component = view;
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        this.modified = false;
        this.hasMatch = false;
        this.editable = false;
        view.setFullMessageEditable(false);
        textArea.setToolTipText(null);
        this.updatedRequest = null;
        this.lastError = null;

        this.toolSourceName = HttpContextMapper.toolSource(creationContext.toolSource(), Constants.ToolSource.ANY);

        if (requestResponse == null || requestResponse.request() == null) {
            currentRequest = null;
            view.setOriginalMessage(null);
            view.setBodyText("无可用请求");
            textArea.setEditable(false);
            return;
        }

        currentRequest = requestResponse.request();
        view.setOriginalMessage(currentRequest);
        String body = currentRequest.bodyToString();
        if (body == null) {
            body = "";
        }

        HttpRequestContext displayContext = HttpContextMapper.request(
                currentRequest, toolSourceName, null);
        RuleProcessingService.HeaderDisplayOutcome headerDisplay = processingService.processRequestHeadersForDisplay(
                displayContext, view.originalPrefix());
        view.setDisplayPrefix(headerDisplay.isSuccess() ? headerDisplay.getContent() : view.originalPrefix());
        if (!headerDisplay.isSuccess())
            textArea.setToolTipText("Header display transform failed; original headers retained: "
                    + headerDisplay.getError());

        ProcessingOutcome outcome = processingService.processRequestForPhase(
                displayContext, displayContext.getBody(), Constants.ExecutionPhase.DISPLAY);

        if (!outcome.isMatched()) {
            hasMatch = false;
            view.setBodyText("未匹配到解密规则\n\n" + body);
            textArea.setEditable(false);
            return;
        }

        if (outcome.isSuccess()) {
            hasMatch = true;
            view.setBodyText(requireNonNullElse(outcome.getContent(), ""));
            editable = creationContext.editorMode() != EditorMode.READ_ONLY
                    && processingService.canPrepareEditedRequest(requestContext(currentRequest, view.bodyText()));
            view.setFullMessageEditable(editable);
            if (!editable && creationContext.editorMode() != EditorMode.READ_ONLY)
                textArea.setToolTipText("Read-only: add an encrypt body/field action with editor-send to edit this request.");
        } else {
            hasMatch = false;
            lastError = outcome.getError();
            view.setBodyText("解密失败: " + lastError + "\n\n" + body);
            textArea.setEditable(false);
        }
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        if (requestResponse == null || requestResponse.request() == null) {
            return false;
        }

        HttpRequest request = requestResponse.request();
        HttpRequestContext context = HttpContextMapper.request(request,
                HttpContextMapper.toolSource(creationContext.toolSource(), Constants.ToolSource.ANY), null);

        return processingService.shouldProvidePlaintextRequestEditor(context);
    }

    @Override
    public HttpRequest getRequest() {
        if (!hasMatch || !editable || currentRequest == null) return currentRequest;
        long revision = processingService.getRuleRevision();
        if (updatedRequest != null && preparedRevision == revision) return updatedRequest;
        updatedRequest = null;
        if (!modified) return currentRequest;
        try {
            String plaintext = view.bodyText();
            HttpRequest edited = currentRequest;
            if (view.headersChanged()) {
                String prefix = view.prefixText();
                EditorMessageSupport.validatePrefix(prefix, false);
                edited = requestFactory.apply(currentRequest.httpService(), prefix);
                if (edited == null) throw new IllegalArgumentException("Unable to parse edited HTTP headers.");
            }
            var context = requestContext(edited, plaintext);
            var outcome = encryptForSend(context, plaintext);
            byte[] ciphertext = EditorMessageSupport.ciphertext(outcome, context.getBodyBytes(), context.getHeaders());
            HttpRequest candidate = edited.withBody(burp.api.montoya.core.ByteArray.byteArray(ciphertext));
            for (var header : outcome.getModifiedHeaders().entrySet())
                candidate = candidate.withHeader(header.getKey(), header.getValue());
            candidate = EditorMessageSupport.normalizeFraming(candidate);
            if (revision != processingService.getRuleRevision())
                throw new IllegalStateException("Rules changed while preparing this request; retry with the current rules.");
            updatedRequest = candidate;
            preparedRevision = revision;
            lastError = null;
            textArea.setToolTipText(null);
            // A host read is not a commit: keep modified until the host establishes a new baseline.
            return updatedRequest;
        } catch (Exception error) {
            reportSendError(error.getMessage());
            return currentRequest;
        }
    }

    @Override
    public String caption() {
        return "Universal Crypto";
    }

    @Override
    public Component uiComponent() {
        return component;
    }

    @Override
    public Selection selectedData() {
        return null;
    }

    @Override
    public boolean isModified() {
        return modified;
    }

    private void markModified() {
        if (!hasMatch || !editable || view.isRendering()) {
            return;
        }
        this.modified = view.isContentModified();
        this.updatedRequest = null;
    }

    private void reportSendError(String error) {
        lastError = error;
        textArea.setToolTipText("Send failed; original request retained: " + error);
        if (api != null && api.logging() != null) api.logging().logToError("Universal Crypto editor-send failed: " + error);
    }

    private ProcessingOutcome encryptForSend(HttpRequestContext context, String plaintext) {
        if (!processingService.canPrepareEditedRequest(context))
            return ProcessingOutcome.failure("No editor-send encryption action matched the edited request.", List.of());
        return processingService.processRequestForPhase(context, plaintext, Constants.ExecutionPhase.EDITOR_SEND);
    }

    private HttpRequestContext requestContext(HttpRequest request, String body) {
        return HttpContextMapper.request(request, toolSourceName, null).withBody(body);
    }

    private static String requireNonNullElse(String value, String defaultValue) {
        return value != null ? value : defaultValue;
    }
}
