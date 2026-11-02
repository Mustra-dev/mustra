import { snippet } from "@codemirror/autocomplete";
import { syntaxTree } from "@codemirror/language";

const kinds = { 2: "method", 3: "function", 5: "property", 6: "variable", 7: "class", 9: "namespace", 14: "keyword", 21: "constant" };

export function scriptCompletions(complete, onStatus = () => {}) {
  return async context => {
    const token = syntaxTree(context.state).resolveInner(context.pos, -1);
    if (/comment|string/i.test(token.name)) return null;
    if (token.name === "invalid" && /^["']/.test(context.state.sliceDoc(token.from, token.to))) return null;
    const word = context.matchBefore(/[\w$:-]+/);
    if (!context.explicit && (!word || word.text.length < 2)) return null;
    const doc = context.state.doc;
    const line = doc.lineAt(context.pos);
    const abort = new AbortController();
    context.addEventListener("abort", () => { abort.abort(); onStatus(""); }, { onDocChange: true });
    onStatus("Loading suggestions…");
    try {
      const items = await complete(doc.toString(), { line: line.number - 1, character: context.pos - line.from }, abort.signal);
      if (context.aborted) return null;
      onStatus("");
      return {
        from: word?.from ?? context.pos,
        // The language service has already matched/ranked context-sensitive results.
        filter: false,
        options: items.map(item => ({
          label: item.label, detail: item.detail, type: kinds[item.kind] || "text",
          apply: (view, completion, from, to) => {
            const start = item.from ?? from, end = item.to ?? to;
            if (start < 0 || end < start || end > view.state.doc.length) return;
            if (item.snippet) snippet(item.text)(view, completion, start, end);
            else view.dispatch({ changes: { from: start, to: end, insert: item.text }, selection: { anchor: start + item.text.length }, userEvent: "input.complete" });
          },
        })),
      };
    } catch {
      if (!context.aborted) onStatus("Suggestions unavailable. Try Ctrl-Space again.");
      return null;
    }
  };
}
