import assert from "node:assert/strict";
import test from "node:test";
import { CompletionContext } from "@codemirror/autocomplete";
import { EditorState } from "@codemirror/state";
import { ensureSyntaxTree, StreamLanguage } from "@codemirror/language";
import { shell } from "@codemirror/legacy-modes/mode/shell";
import { powerShell } from "@codemirror/legacy-modes/mode/powershell";
import { scriptCompletions } from "./completions.js";

function context(language, doc) {
  const state = EditorState.create({ doc, extensions: [StreamLanguage.define(language === "powershell" ? powerShell : shell)] });
  ensureSyntaxTree(state, doc.length, 100);
  return new CompletionContext(state, doc.length, true);
}

test("completion forwards the document and UTF-16 cursor position to the language service", async () => {
  const doc = "# 😀\n$sensorVariable = 1\n$sensorV";
  let request;
  const result = await scriptCompletions(async (script, position) => {
    request = { script, position };
    return [{ label: "$sensorVariable", text: "$sensorVariable", kind: 6 }];
  })(context("powershell", doc));
  assert.deepEqual(request, { script: doc, position: { line: 2, character: 8 } });
  assert.equal(result.options[0].label, "$sensorVariable");
  assert.equal(result.options[0].type, "variable");
});

test("completion applies the server's replacement range", async () => {
  const ctx = context("powershell", "Get-ChildItem -Pa");
  const result = await scriptCompletions(async () => [{ label: "Path", text: "-Path", from: 14, to: 17, kind: 5 }])(ctx);
  const view = { state: ctx.state, dispatch(spec) { this.state = this.state.update(spec).state; } };
  result.options[0].apply(view, result.options[0], result.from, ctx.pos);
  assert.equal(view.state.doc.toString(), "Get-ChildItem -Path");
});

test("comments and quoted strings do not request command completions", async () => {
  for (const language of ["shell", "powershell"]) {
    const source = scriptCompletions(() => { throw new Error("unexpected request"); });
    assert.equal(await source(context(language, "# Get-")), null);
    assert.equal(await source(context(language, 'echo "Get-')), null);
  }
});

test("unavailable completion service is visible and has no custom word-list fallback", async () => {
  const statuses = [];
  const result = await scriptCompletions(async () => { throw new Error("unavailable"); }, value => statuses.push(value))(context("shell", "sensor_"));
  assert.equal(result, null);
  assert.match(statuses.at(-1), /unavailable/);
});
