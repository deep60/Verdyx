// Write /privacy and /terms as complete static HTML after `vite build`.
//
// The app renders every page in the browser, so a crawler that doesn't run
// JavaScript (Google's OAuth branding review among them) sees an empty page.
// These two files carry the full text; the app still loads on top of them and
// takes over as usual.
import { readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const publicDir = path.join(root, "dist/public");
const ssrDir = path.join(root, "dist/prerender");

const escape = (s) =>
  s.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");

const { renderLegalPages } = await import(pathToFileURL(path.join(ssrDir, "legal-prerender.js")).href);
const template = await readFile(path.join(publicDir, "index.html"), "utf8");

if (!template.includes('<div id="root"></div>') || !template.includes("</head>")) {
  throw new Error("prerender-legal: dist/public/index.html no longer has an empty #root and a </head>");
}

for (const page of renderLegalPages()) {
  const title = `${page.title} | Verdyx`;
  const url = `https://verdyx.dev/${page.path}`;
  const head = [
    `<title>${escape(title)}</title>`,
    `<meta name="description" content="${escape(page.description)}" />`,
    `<link rel="canonical" href="${url}" />`,
    `<meta property="og:title" content="${escape(title)}" />`,
    `<meta property="og:description" content="${escape(page.description)}" />`,
    `<meta property="og:url" content="${url}" />`,
  ].join("\n    ");

  const html = template
    .replace("</head>", `    ${head}\n  </head>`)
    .replace('<div id="root"></div>', `<div id="root">${page.html}</div>`);

  // `privacy.html`, not `privacy/index.html`: Cloudflare Pages serves it at
  // /privacy directly, where a directory would first redirect to /privacy/.
  await writeFile(path.join(publicDir, `${page.path}.html`), html);
  console.log(`prerendered /${page.path} (${page.html.length} bytes of content)`);
}

await rm(ssrDir, { recursive: true, force: true });
