package com.universal.crypto.ui.editor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import com.universal.crypto.engine.RuleProcessingService;

/**
 * Provider responsible for creating plaintext-aware HTTP request editors.
 */
public class PlaintextHttpRequestEditorProvider implements HttpRequestEditorProvider {

    private final MontoyaApi api;
    private final RuleProcessingService processingService;

    public PlaintextHttpRequestEditorProvider(MontoyaApi api,
                                              RuleProcessingService processingService) {
        this.api = api;
        this.processingService = processingService;
    }

    @Override
    public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext creationContext) {
        return new PlaintextHttpRequestEditor(api, processingService, creationContext);
    }
}

