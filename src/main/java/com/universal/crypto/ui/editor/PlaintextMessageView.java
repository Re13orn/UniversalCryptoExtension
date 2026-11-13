package com.universal.crypto.ui.editor;

import burp.api.montoya.http.message.HttpMessage;
import burp.api.montoya.MontoyaApi;
import java.awt.Font;
import java.awt.event.HierarchyEvent;

import javax.swing.*;
import javax.swing.event.PopupMenuEvent;
import javax.swing.event.PopupMenuListener;
import javax.swing.text.AbstractDocument;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.DocumentFilter;
import java.awt.BorderLayout;
import java.awt.Color;
import org.fife.ui.rsyntaxtextarea.*;
import org.fife.ui.rsyntaxtextarea.modes.JsonTokenMaker;
import org.fife.ui.rtextarea.RTextScrollPane;
import javax.swing.text.Segment;
import javax.swing.text.DefaultEditorKit;
import java.nio.charset.StandardCharsets;

/** HTTP prefix and plaintext body in one editor, editable when the host permits it. */
class PlaintextMessageView extends JPanel {
    private final MontoyaApi api;
    private final RTextScrollPane scroll;
    private final RSyntaxTextArea text = new IsolatedSyntaxTextArea();
    private final JRadioButtonMenuItem pretty = new JRadioButtonMenuItem("Pretty JSON", true);
    private final JRadioButtonMenuItem raw = new JRadioButtonMenuItem("Raw");
    private String rawBody = "";
    private String renderedBody = "";
    private String baselineBody = "";
    private boolean headersEditable;
    private String workingPrefix = "";
    private boolean jsonBody;
    private final JCheckBoxMenuItem showHeaders = new JCheckBoxMenuItem("Show original HTTP headers", true);
    private String originalPrefix = "";
    private String displayedPrefix = "";
    private int bodyStart;
    private boolean rendering;

    PlaintextMessageView() { this(null); }

    PlaintextMessageView(MontoyaApi api) {
        super(new BorderLayout());
        this.api = api;
        text.setLineWrap(true);
        text.setWrapStyleWord(true);
        text.setFont(editorFont());
        text.setEditable(false);
        text.setAutoIndentEnabled(false);
        text.setCloseCurlyBraces(false);
        text.setCloseMarkupTags(false);
        text.setBracketMatchingEnabled(false);
        text.setHighlightCurrentLine(false);
        text.getActionMap().put(DefaultEditorKit.selectAllAction, new AbstractAction() {
            @Override public void actionPerformed(java.awt.event.ActionEvent e) { selectBodyOrAll(); }
        });
        configureColors();
        ((RSyntaxDocument) text.getDocument()).setSyntaxStyle(new MessageTokens());
        showHeaders.setToolTipText("Show request/status line and HTTP headers. Content-Length is updated when sending.");
        JPopupMenu menu = new JPopupMenu();
        menu.add(showHeaders);
        ButtonGroup formats = new ButtonGroup();
        formats.add(pretty); formats.add(raw);
        menu.add(pretty); menu.add(raw);
        pretty.addActionListener(e -> changePresentation());
        raw.addActionListener(e -> changePresentation());
        menu.addSeparator();
        JMenuItem cut = new JMenuItem("Cut");
        cut.addActionListener(e -> text.cut());
        JMenuItem copy = new JMenuItem("Copy");
        copy.addActionListener(e -> text.copy());
        JMenuItem paste = new JMenuItem("Paste");
        paste.addActionListener(e -> text.paste());
        JMenuItem selectAll = new JMenuItem("Select all");
        selectAll.addActionListener(e -> selectBodyOrAll());
        menu.add(cut);
        menu.add(copy);
        menu.add(paste);
        menu.add(selectAll);
        menu.addPopupMenuListener(new PopupMenuListener() {
            public void popupMenuWillBecomeVisible(PopupMenuEvent e) {
                try { pretty.setEnabled(JsonPresentation.pretty(bodyText()) != null); }
                catch (IllegalArgumentException error) { pretty.setEnabled(false); }
                boolean selection = text.getSelectionStart() != text.getSelectionEnd();
                boolean editableBody = text.isEditable() && (headersEditable || text.getSelectionStart() >= bodyStart);
                cut.setEnabled(editableBody && selection);
                copy.setEnabled(selection);
                paste.setEnabled(editableBody);
            }
            public void popupMenuWillBecomeInvisible(PopupMenuEvent e) { }
            public void popupMenuCanceled(PopupMenuEvent e) { }
        });
        text.setComponentPopupMenu(menu);
        scroll = new RTextScrollPane(text, true);
        scroll.getGutter().setBackground(text.getBackground());
        Color gutterBackground = text.getBackground();
        boolean darkGutter = gutterBackground.getRed() + gutterBackground.getGreen() + gutterBackground.getBlue() < 384;
        scroll.getGutter().setBorderColor(new Color(darkGutter ? 0x505050 : 0xD0D0D0));
        scroll.getGutter().setLineNumberColor(text.getForeground().darker());
        scroll.getGutter().setLineNumberFont(text.getFont());
        scroll.setBorder(BorderFactory.createEmptyBorder());
        add(scroll, BorderLayout.CENTER);
        addHierarchyListener(e -> {
            if ((e.getChangeFlags() & HierarchyEvent.SHOWING_CHANGED) != 0 && isShowing()) refreshEditorFont();
        });
        ((AbstractDocument) text.getDocument()).setDocumentFilter(new DocumentFilter() {
            private boolean allowed(int offset) { return rendering || headersEditable || offset >= bodyStart; }
            private void prepare(FilterBypass fb, int offset, int length, String value) throws BadLocationException {
                if (rendering) return;
                if (headersEditable && showHeaders.isSelected() && !workingPrefix.isEmpty()) {
                    String old = fb.getDocument().getText(0, fb.getDocument().getLength());
                    String next = old.substring(0, offset) + value + old.substring(offset + length);
                    int boundary = prefixEnd(next);
                    bodyStart = boundary >= 0 ? boundary : Math.min(next.length(), Math.max(0, bodyStart + value.length() - length));
                }
            }
            @Override public void insertString(FilterBypass fb, int offset, String value, AttributeSet attrs) throws BadLocationException {
                if (allowed(offset)) { prepare(fb, offset, 0, value == null ? "" : value); super.insertString(fb, offset, value, attrs); }
            }
            @Override public void remove(FilterBypass fb, int offset, int length) throws BadLocationException {
                if (allowed(offset)) { prepare(fb, offset, length, ""); super.remove(fb, offset, length); }
            }
            @Override public void replace(FilterBypass fb, int offset, int length, String value, AttributeSet attrs) throws BadLocationException {
                if (allowed(offset)) { prepare(fb, offset, length, value == null ? "" : value); super.replace(fb, offset, length, value, attrs); }
            }
        });
        showHeaders.addActionListener(e -> {
            // The checkbox already changed; capture the previously visible prefix first.
            boolean newChoice = showHeaders.isSelected();
            showHeaders.setSelected(!newChoice);
            try {
                String body = bodyText();
                workingPrefix = prefixText();
                showHeaders.setSelected(newChoice);
                render(body);
            } catch (IllegalArgumentException error) { text.setToolTipText(error.getMessage()); }
        });
    }

    void setOriginalMessage(HttpMessage message) {
        refreshEditorFont();
        headersEditable = false;
        originalPrefix = message == null ? "" : readPrefix(message);
        displayedPrefix = originalPrefix;
        workingPrefix = displayedPrefix;
    }

    /**
     * Replace only the header text rendered in this editor. The original prefix remains the
     * send/write-back baseline, so a display transform cannot leak into an edited request.
     */
    void setDisplayPrefix(String prefix) {
        displayedPrefix = prefix == null ? originalPrefix : prefix;
        workingPrefix = displayedPrefix;
    }

    String originalPrefix() {
        return originalPrefix;
    }

    private static String readPrefix(HttpMessage message) {
        // Some host message wrappers do not expose a usable bodyOffset. Prefer
        // the actual serialized separator, preserving header order and duplicates.
        try {
            String serialized = new String(message.toByteArray().getBytes(), StandardCharsets.ISO_8859_1);
            int boundary = prefixEnd(serialized);
            int firstLineEnd = serialized.indexOf('\n');
            String firstLine = firstLineEnd < 0 ? serialized : serialized.substring(0, firstLineEnd).stripTrailing();
            if (boundary > 0 && (firstLine.startsWith("HTTP/")
                    || firstLine.matches("[^\\s]+ [^\\s]+ HTTP/[^\\s]+"))) {
                return serialized.substring(0, boundary);
            }
        } catch (RuntimeException ignored) { /* Fall back to structured host metadata. */ }
        String version = message.httpVersion();
        if (version == null || version.isBlank()) version = "HTTP/1.1";
        StringBuilder prefix = new StringBuilder();
        if (message instanceof burp.api.montoya.http.message.requests.HttpRequest request) {
            prefix.append(request.method()).append(' ').append(request.path()).append(' ').append(version);
        } else if (message instanceof burp.api.montoya.http.message.responses.HttpResponse response) {
            prefix.append(version).append(' ').append(response.statusCode());
            if (response.reasonPhrase() != null && !response.reasonPhrase().isEmpty())
                prefix.append(' ').append(response.reasonPhrase());
        } else {
            throw new IllegalArgumentException("Unable to read HTTP request/status line.");
        }
        prefix.append("\r\n");
        if (message.headers() != null) for (var header : message.headers())
            prefix.append(header.name()).append(": ").append(header.value()).append("\r\n");
        return prefix.append("\r\n").toString();
    }

    void setBodyText(String body) { baselineBody = body == null ? "" : body; render(baselineBody); }
    String bodyText() {
        if (showHeaders.isSelected() && !workingPrefix.isEmpty()) requirePrefixEnd();
        String visible = text.getText().substring(bodyStart);
        return visible.equals(renderedBody) ? rawBody : visible;
    }
    boolean isContentModified() {
        try { return headersChanged() || !bodyText().equals(baselineBody); }
        catch (IllegalArgumentException error) { return true; }
    }

    String prefixText() {
        return showHeaders.isSelected() && !workingPrefix.isEmpty()
                ? text.getText().substring(0, requirePrefixEnd()) : workingPrefix;
    }
    boolean headersChanged() { return !prefixText().equals(displayedPrefix); }

    private int requirePrefixEnd() {
        int boundary = prefixEnd(text.getText());
        if (boundary < 0) throw new IllegalArgumentException("HTTP headers must end with a blank line.");
        bodyStart = boundary;
        return boundary;
    }

    private static int prefixEnd(String message) {
        int crlf = message.indexOf("\r\n\r\n"), lf = message.indexOf("\n\n");
        if (crlf >= 0 && (lf < 0 || crlf <= lf)) return crlf + 4;
        return lf < 0 ? -1 : lf + 2;
    }

    private void changePresentation() {
        try { String body = bodyText(); workingPrefix = prefixText(); render(body); }
        catch (IllegalArgumentException error) { text.setToolTipText(error.getMessage()); }
    }

    void setFullMessageEditable(boolean editable) {
        headersEditable = editable;
        setBodyEditable(editable);
    }
    void setBodyEditable(boolean editable) {
        text.setEditable(editable);
        if (editable) text.setCaretPosition(bodyStart);
    }

    private void selectBodyOrAll() {
        if (text.isEditable() && !headersEditable) text.select(bodyStart, text.getDocument().getLength());
        else text.selectAll();
    }

    JTextArea textArea() { return text; }
    boolean isRendering() { return rendering; }

    private Font editorFont() {
        if (api != null) {
            try {
                Font font = api.userInterface().currentEditorFont();
                if (font != null) return font;
            } catch (RuntimeException ignored) { /* Allow offline views and incomplete API test doubles. */ }
        }
        return new Font(Font.MONOSPACED, Font.PLAIN, 12);
    }

    private void refreshEditorFont() {
        Font font = editorFont();
        if (font.equals(text.getFont())) return;
        text.setFont(font);
        SyntaxScheme scheme = (SyntaxScheme) text.getSyntaxScheme().clone();
        for (Style style : scheme.getStyles()) if (style != null) style.font = font;
        text.setSyntaxScheme(scheme);
        scroll.getGutter().setLineNumberFont(font);
        revalidate(); repaint();
    }

    private void configureColors() {
        Color background = UIManager.getColor("TextArea.background");
        Color foreground = UIManager.getColor("TextArea.foreground");
        if (background == null) background = Color.WHITE;
        if (foreground == null) foreground = Color.BLACK;
        boolean dark = background.getRed() + background.getGreen() + background.getBlue() < 384;
        // Burp's dark HTTP editor uses a darker surface than Swing's default text area.
        if (dark) background = new Color(0x2B2B2B);
        text.setBackground(background); text.setForeground(foreground); text.setCaretColor(foreground);
        SyntaxScheme scheme = new SyntaxScheme(text.getFont(), false);
        for (Style style : scheme.getStyles()) if (style != null) { style.foreground = foreground; style.font = text.getFont(); }
        Color header = new Color(dark ? 0xD1E8F9 : 0x005A9C);
        Color key = new Color(dark ? 0xE9C062 : 0x795E26);
        Color string = new Color(dark ? 0x93C763 : 0x36802D);
        Color number = new Color(dark ? 0x79C1F4 : 0x005A9C);
        Color literal = new Color(dark ? 0xF89E57 : 0xA34D00);
        // HTTP names have their own token type: JSON null is a RESERVED_WORD.
        scheme.getStyle(TokenTypes.DATA_TYPE).foreground = header;
        scheme.getStyle(TokenTypes.VARIABLE).foreground = key;
        scheme.getStyle(TokenTypes.LITERAL_STRING_DOUBLE_QUOTE).foreground = string;
        scheme.getStyle(TokenTypes.LITERAL_NUMBER_DECIMAL_INT).foreground = number;
        scheme.getStyle(TokenTypes.LITERAL_NUMBER_FLOAT).foreground = number;
        scheme.getStyle(TokenTypes.LITERAL_BOOLEAN).foreground = literal;
        scheme.getStyle(TokenTypes.RESERVED_WORD).foreground = literal;
        text.setSyntaxScheme(scheme);
    }

    /** Highlight the HTTP prefix independently from the plaintext body. */
    private final class MessageTokens extends AbstractTokenMaker {
        private final JsonTokenMaker json = new JsonTokenMaker();
        public TokenMap getWordsToHighlight() { return new TokenMap(); }
        @Override public int getLastTokenTypeOnLine(Segment line, int initial) { return TokenTypes.NULL; }
        public Token getTokenList(Segment line, int initial, int startOffset) {
            if (startOffset >= bodyStart) {
                if (jsonBody) return json.getTokenList(line, TokenTypes.NULL, startOffset);
            }
            resetTokenList();
            int begin = line.offset, end = begin + line.count - 1;
            if (startOffset < bodyStart) {
                int split = begin;
                while (split <= end && line.array[split] != (startOffset == 0 ? ' ' : ':')) split++;
                if (split <= end) {
                    addToken(line, begin, split, TokenTypes.DATA_TYPE, startOffset);
                    if (split < end) addToken(line, split + 1, end, TokenTypes.IDENTIFIER, startOffset + split + 1 - begin);
                } else if (begin <= end) addToken(line, begin, end, TokenTypes.IDENTIFIER, startOffset);
            } else if (begin <= end) addToken(line, begin, end, TokenTypes.IDENTIFIER, startOffset);
            addNullToken();
            return firstToken;
        }
    }

    private void render(String body) {
        String prefix = showHeaders.isSelected() ? workingPrefix : "";
        rendering = true;
        try {
            rawBody = body;
            String leading = body.stripLeading();
            jsonBody = leading.startsWith("{") || leading.startsWith("[");
            bodyStart = prefix.length();
            String formatted = pretty.isSelected() ? JsonPresentation.pretty(body) : null;
            renderedBody = formatted == null ? body : formatted;
            text.setText(prefix + renderedBody);
            text.discardAllEdits();
            text.setCaretPosition(text.isEditable() ? bodyStart : 0);
        } finally { rendering = false; }
    }
}
