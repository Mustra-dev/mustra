import { Compartment, EditorState } from "@codemirror/state";
import { EditorView, drawSelection, highlightActiveLine, highlightActiveLineGutter, highlightSpecialChars, keymap, lineNumbers } from "@codemirror/view";
import { defaultKeymap, history, historyKeymap, indentWithTab } from "@codemirror/commands";
import { bracketMatching, HighlightStyle, indentOnInput, StreamLanguage, syntaxHighlighting } from "@codemirror/language";
import { openSearchPanel, search, searchKeymap } from "@codemirror/search";
import { go } from "@codemirror/legacy-modes/mode/go";
import { python } from "@codemirror/legacy-modes/mode/python";
import { standardSQL } from "@codemirror/legacy-modes/mode/sql";
import { shell } from "@codemirror/legacy-modes/mode/shell";
import { powerShell } from "@codemirror/legacy-modes/mode/powershell";
import { autocompletion, completionKeymap } from "@codemirror/autocomplete";
import { linter, lintGutter, setDiagnostics } from "@codemirror/lint";
import { scriptCompletions } from "./completions.js";
import { tags } from "@lezer/highlight";

const highlighting = HighlightStyle.define([
  { tag: tags.keyword, color: "var(--cs-code-keyword)" },
  { tag: [tags.string, tags.special(tags.string)], color: "var(--cs-code-string)" },
  { tag: [tags.number, tags.bool, tags.atom], color: "var(--cs-code-number)" },
  { tag: tags.comment, color: "var(--text-muted)", fontStyle: "italic" },
  { tag: [tags.variableName, tags.definition(tags.variableName)], color: "var(--cs-code-variable)" },
  { tag: [tags.function(tags.variableName), tags.standard(tags.variableName), tags.typeName], color: "var(--cs-code-function)" },
  { tag: [tags.operator, tags.meta], color: "var(--cs-code-keyword)" },
  { tag: tags.invalid, textDecoration: "underline wavy var(--off)" },
]);

// The console serves pages under a nonce CSP and stamps this bundle's
// <script> with the nonce. CodeMirror injects <style> elements; giving them
// the same nonce keeps the editor working if style-src ever drops
// 'unsafe-inline'. currentScript is only set while the bundle first runs.
const cspNonce = (document.currentScript && document.currentScript.nonce) || "";

// Each platform owns a view so tab changes retain selection, scroll, and undo.
// Keep this adapter independent of sensors; execution always belongs to the API.
window.MustraScriptEditor = function(parent, { language, label, onChange, validate, complete, onCompletionStatus }) {
  const access = new Compartment();
  const syntax = new Compartment();
  const mode = name => StreamLanguage.define(name === 'go' ? go : name === 'python' ? python : name === 'wql' ? standardSQL : name === 'powershell' ? powerShell : name === 'batch' ? {token(stream) {if(stream.match(/^(rem\b|::).*/i)) return 'comment'; if(stream.match(/%[^%]+%|![^!]+!/)) return 'variable-2';if(stream.match(/\b(if|else|for|in|do|set|echo|exit|call|goto|setlocal|endlocal)\b/i)) return 'keyword';stream.next();return null;}} : shell);
  const extensions = [
    lineNumbers(), highlightSpecialChars(), history(), drawSelection(),
    highlightActiveLine(), highlightActiveLineGutter(), indentOnInput(), bracketMatching(),
    syntax.of(mode(language)),
    syntaxHighlighting(highlighting), search({ top: true }),
    autocompletion({ override: complete ? [scriptCompletions(complete, onCompletionStatus)] : [], activateOnTypingDelay: 400 }),
    ...(validate ? [lintGutter(), linter(async view => {
      try { return await validate(view.state.doc.toString()); }
      catch { return [{ from: 0, to: 0, severity: "warning", message: "Syntax check unavailable. Saving will check syntax again." }]; }
    }, { delay: 500 })] : []),
    keymap.of([...completionKeymap, ...searchKeymap, ...defaultKeymap, ...historyKeymap, indentWithTab]),
    EditorState.tabSize.of(2),
    ...(cspNonce ? [EditorView.cspNonce.of(cspNonce)] : []),
    EditorView.contentAttributes.of({ "aria-label": label, "aria-describedby": "cs-script-help cs-script-error", spellcheck: "false" }),
    access.of([EditorState.readOnly.of(false), EditorView.editable.of(true)]),
    EditorView.updateListener.of(update => { if (update.docChanged) onChange(); }),
  ];
  const view = new EditorView({ parent, state: EditorState.create({ extensions }) });
  return {
    setLanguage: name => {language=name;view.dispatch({effects:syntax.reconfigure(mode(name))});},
    setDiagnostics: diagnostics => view.dispatch(setDiagnostics(view.state, diagnostics)),
    getValue: () => view.state.doc.toString(),
    setValue: value => {view.setState(EditorState.create({ doc: value, extensions }));view.dispatch({effects:syntax.reconfigure(mode(language))});},
    setReadOnly: readOnly => view.dispatch({ effects: access.reconfigure([
      EditorState.readOnly.of(readOnly), EditorView.editable.of(!readOnly),
    ]) }),
    focus: () => view.focus(),
    find: () => { openSearchPanel(view); },
    refresh: () => view.requestMeasure(),
  };
};
