import { basicSetup } from "codemirror";
import { EditorView } from "@codemirror/view";
import { EditorState } from "@codemirror/state";
import { javascript } from "@codemirror/lang-javascript";
import { html } from "@codemirror/lang-html";
import { css } from "@codemirror/lang-css";
import { python } from "@codemirror/lang-python";
import { json } from "@codemirror/lang-json";
import { markdown } from "@codemirror/lang-markdown";
import { sql } from "@codemirror/lang-sql";
import { xml } from "@codemirror/lang-xml";
import { oneDark } from "@codemirror/theme-one-dark";

const editorTheme = EditorView.theme({
  "&": {
    height: "100%",
    minHeight: "320px",
    fontSize: "14px",
    backgroundColor: "#0b1222",
    color: "#e6edf7"
  },
  ".cm-scroller": {
    overflow: "auto",
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
    lineHeight: "1.6"
  },
  ".cm-gutters": {
    backgroundColor: "#0b1222",
    borderRight: "1px solid #283653",
    color: "#8b9bb4"
  },
  ".cm-activeLine": { backgroundColor: "rgba(67,140,255,.09)" },
  ".cm-activeLineGutter": { backgroundColor: "rgba(67,140,255,.14)" },
  ".cm-focused": { outline: "3px solid rgba(67,140,255,.24)", outlineOffset: "-3px" },
  "&.cm-focused .cm-cursor": { borderLeftColor: "#8bb8ff" },
  ".cm-selectionBackground, ::selection": { backgroundColor: "#294b79 !important" },
  ".cm-tooltip": {
    backgroundColor: "#17233a",
    border: "1px solid #385071",
    color: "#f4f7fc"
  },
  ".cm-tooltip-autocomplete ul li[aria-selected]": {
    backgroundColor: "#28518a",
    color: "#ffffff"
  }
}, { dark: true });

function languageForFile(fileName = "") {
  const extension = String(fileName).split(".").pop().toLowerCase();
  if (["html", "htm"].includes(extension)) return html();
  if (extension === "css") return css();
  if (["js", "mjs", "cjs", "ts", "tsx", "jsx"].includes(extension)) {
    return javascript({ typescript: ["ts", "tsx"].includes(extension), jsx: ["jsx", "tsx"].includes(extension) });
  }
  if (["py", "pyw"].includes(extension)) return python();
  if (["json", "jsonc"].includes(extension)) return json();
  if (["md", "markdown", "mdx"].includes(extension)) return markdown();
  if (["sql"].includes(extension)) return sql();
  if (["xml", "svg"].includes(extension)) return xml();
  return [];
}

export function mountEditor({ host, value = "", fileName = "", onChange = () => {}, readOnly = false } = {}) {
  if (!(host instanceof HTMLElement)) throw new TypeError("Un conteneur HTML est requis pour l’éditeur.");
  if (host.__cloudIDEView) host.__cloudIDEView.destroy();

  const state = EditorState.create({
    doc: String(value),
    extensions: [
      basicSetup,
      oneDark,
      editorTheme,
      languageForFile(fileName),
      EditorView.lineWrapping,
      EditorState.readOnly.of(Boolean(readOnly)),
      EditorView.editable.of(!readOnly),
      EditorView.updateListener.of(update => {
        if (update.docChanged) onChange(update.state.doc.toString());
      })
    ]
  });

  const view = new EditorView({ state, parent: host });
  host.__cloudIDEView = view;

  return {
    getValue: () => view.state.doc.toString(),
    setValue: nextValue => {
      const next = String(nextValue ?? "");
      if (next === view.state.doc.toString()) return;
      view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: next } });
    },
    focus: () => view.focus(),
    setReadOnly: nextReadOnly => view.dispatch({
      effects: EditorView.editable.of(!nextReadOnly)
    }),
    destroy: () => {
      view.destroy();
      if (host.__cloudIDEView === view) delete host.__cloudIDEView;
    },
    view
  };
}
