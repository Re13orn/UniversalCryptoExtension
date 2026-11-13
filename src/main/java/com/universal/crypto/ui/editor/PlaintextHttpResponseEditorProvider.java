package com.universal.crypto.ui.editor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.*;
import com.universal.crypto.engine.RuleProcessingService;

/** Plaintext view, optionally editable with an explicit response-editor-send rule. */
public class PlaintextHttpResponseEditorProvider implements HttpResponseEditorProvider {
    private final RuleProcessingService service;
    private final MontoyaApi api;
    public PlaintextHttpResponseEditorProvider(RuleProcessingService service) { this(null, service); }
    public PlaintextHttpResponseEditorProvider(MontoyaApi api, RuleProcessingService service) {
        this.api = api; this.service = service;
    }
    public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext creation) {
        return new PlaintextHttpResponseEditor(api, service, creation);
    }
}
