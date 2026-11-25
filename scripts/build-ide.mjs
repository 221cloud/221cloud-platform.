import { rm } from "node:fs/promises";
import { build } from "esbuild";

await rm("public/assets/ide-editor", { recursive: true, force: true });
await rm("public/assets/ide-editor.js", { force: true });

const result = await build({
  entryPoints: ["src/ide-editor/main.js"],
  bundle: true,
  splitting: true,
  format: "esm",
  target: "es2022",
  minify: true,
  outdir: "public/assets/ide-editor",
  entryNames: "main",
  chunkNames: "chunks/[name]-[hash]",
  metafile: true
});

const outputs = Object.entries(result.metafile.outputs);
const totalBytes = outputs.reduce((sum, [, output]) => sum + output.bytes, 0);
console.log("CodeMirror : " + outputs.length + " fichier(s) généré(s), " + totalBytes + " octets au total.");
