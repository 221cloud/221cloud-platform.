import { readFileSync, statSync } from "node:fs";
import { gzipSync } from "node:zlib";

const html = readFileSync("public/index.html", "utf8");
const blocks = [...html.matchAll(/<script\\b([^>]*)>([\\s\\S]*?)<\\/script\\s*>/gi)];
let checked = 0;

for (const [, attributes, code] of blocks) {
  if (/\\bsrc\\s*=/.test(attributes) || !code.trim()) continue;
  try {
    new Function(code);
    checked++;
  } catch (error) {
    console.error(`Inline script ${checked + 1}: ${error.message}`);
    process.exitCode = 1;
  }
}

if (process.exitCode) process.exit(process.exitCode);
const bundlePath = "public/assets/ide-editor.js";
const bundle = readFileSync(bundlePath);
console.log(`Syntaxe HTML/JavaScript : ${checked} bloc(s) intégré(s) vérifié(s).`);
console.log(`Bundle CodeMirror : ${statSync(bundlePath).size} octets ; gzip : ${gzipSync(bundle).length} octets.`);
