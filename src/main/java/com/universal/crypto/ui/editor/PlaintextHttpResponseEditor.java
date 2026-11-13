package com.universal.crypto.ui.editor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.*;
import com.universal.crypto.engine.RuleProcessingService;
import com.universal.crypto.handler.HttpResponseContext;
import com.universal.crypto.model.Constants;
import com.universal.crypto.burp.HttpContextMapper;

import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.Component;
import java.util.function.Function;

/** A host-editable response is re-encrypted only after an actual plaintext edit. */
class PlaintextHttpResponseEditor implements ExtensionProvidedHttpResponseEditor {
    private final MontoyaApi api;
    private final RuleProcessingService service;
    private final EditorCreationContext creation;
    private final Function<String,HttpResponse> responseFactory;
    private final PlaintextMessageView view;
    private HttpRequestResponse message;
    private HttpResponse original, prepared;
    private long preparedRevision;
    private boolean modified, editable;

    PlaintextHttpResponseEditor(MontoyaApi api, RuleProcessingService service, EditorCreationContext creation) {
        this(api, service, creation, HttpResponse::httpResponse);
    }

    PlaintextHttpResponseEditor(MontoyaApi api, RuleProcessingService service, EditorCreationContext creation,
                               Function<String,HttpResponse> responseFactory) {
        this.api = api; this.service = service; this.creation = creation; this.responseFactory = responseFactory;
        view = new PlaintextMessageView(api);
        view.textArea().getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { changed(); }
            public void removeUpdate(DocumentEvent e) { changed(); }
            public void changedUpdate(DocumentEvent e) { changed(); }
            private void changed() {
                if (editable && !view.isRendering()) { modified = view.isContentModified(); prepared = null; }
            }
        });
    }

    private HttpResponseContext contextFor(HttpRequestResponse pair, HttpResponse response) {
        if (pair == null || pair.request() == null || response == null) return null;
        return HttpContextMapper.response(pair.request(), response,
                HttpContextMapper.toolSource(creation.toolSource(), Constants.ToolSource.ANY), null);
    }

    public void setRequestResponse(HttpRequestResponse pair) {
        message = pair; original = pair == null ? null : pair.response();
        modified = false; prepared = null; editable = false;
        view.setFullMessageEditable(false); view.textArea().setToolTipText(null);
        try {
            view.setOriginalMessage(original);
            var context = contextFor(pair, original);
            var headerDisplay = context == null ? null
                    : service.processResponseHeadersForDisplay(context, view.originalPrefix());
            view.setDisplayPrefix(headerDisplay == null || !headerDisplay.isSuccess()
                    ? view.originalPrefix() : headerDisplay.getContent());
            if (headerDisplay != null && !headerDisplay.isSuccess())
                view.textArea().setToolTipText("Header display transform failed; original headers retained: "
                        + headerDisplay.getError());
            var result = context == null ? null
                    : service.processResponseForPhase(context, context.getBody(), Constants.ExecutionPhase.RESPONSE_DISPLAY);
            view.setBodyText(result == null || !result.isMatched() ? "未匹配到响应展示规则"
                    : result.isSuccess() ? result.getContent() : "解密失败: " + result.getError());
            if (result != null && result.isMatched() && result.isSuccess() && creation.editorMode() != EditorMode.READ_ONLY) {
                editable = service.canPrepareEditedResponse(context.withBody(view.bodyText()));
                if (!editable) view.textArea().setToolTipText("Read-only: add an encrypt body/field action with response-editor-send to edit this response.");
            }
            view.setFullMessageEditable(editable);
        } catch (Exception e) {
            editable = false; view.setFullMessageEditable(false);
            view.setOriginalMessage(null); view.setBodyText("解密失败: " + e.getMessage());
        }
        view.textArea().setCaretPosition(editable ? view.prefixText().length() : 0);
    }

    public boolean isEnabledFor(HttpRequestResponse pair) {
        try { return service.shouldProvidePlaintextResponseEditor(contextFor(pair, pair == null ? null : pair.response())); }
        catch (Exception e) { return false; }
    }

    public HttpResponse getResponse() {
        long revision = service.getRuleRevision();
        if (prepared != null && preparedRevision == revision) return prepared;
        prepared = null;
        if (!editable || !modified || original == null) return original;
        try {
            String plaintext = view.bodyText();
            HttpResponse edited = original;
            if (view.headersChanged()) {
                String prefix = view.prefixText(); EditorMessageSupport.validatePrefix(prefix, true);
                edited = responseFactory.apply(prefix);
                if (edited == null) throw new IllegalArgumentException("Unable to parse edited HTTP response headers.");
            }
            var context = contextFor(message, edited).withBody(plaintext);
            if (!service.canPrepareEditedResponse(context))
                throw new IllegalArgumentException("No response-editor-send encryption action matched the edited response.");
            var result = service.processResponseForPhase(context, plaintext, Constants.ExecutionPhase.RESPONSE_EDITOR_SEND);
            HttpResponse candidate = edited.withBody(burp.api.montoya.core.ByteArray.byteArray(
                    EditorMessageSupport.ciphertext(result, context.getBodyBytes(), context.getHeaders())));
            for (var header : result.getModifiedHeaders().entrySet()) {
                String name = header.getKey();
                candidate = candidate.hasHeader(name) ? candidate.withUpdatedHeader(name, header.getValue())
                        : candidate.withAddedHeader(name, header.getValue());
            }
            candidate = EditorMessageSupport.normalizeFraming(candidate);
            if (revision != service.getRuleRevision())
                throw new IllegalStateException("Rules changed while preparing this response; retry with the current rules.");
            prepared = candidate;
            preparedRevision = revision;
            view.textArea().setToolTipText(null);
            // A host read is not an acknowledgement: keep modified until a new baseline.
            return prepared;
        } catch (Exception error) {
            String info = "Response edit failed; original ciphertext retained: " + error.getMessage();
            view.textArea().setToolTipText(info);
            if (api != null && api.logging() != null) api.logging().logToError(info);
            return original;
        }
    }

    public String caption() { return "Universal Crypto"; }
    public Component uiComponent() { return view; }
    public Selection selectedData() { return null; }
    public boolean isModified() { return modified; }
}
