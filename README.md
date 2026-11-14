# SBOM Diff

Compare two SBOMs and check their licenses, entirely in your browser. Nothing is uploaded.

**Use it:** https://rozetyp.github.io/sbom-diff/

Drop in two Software Bills of Materials, for example the SBOMs of two releases, and see which components were added, removed or changed. Turn on a license policy to see whether a release pulls in GPL, AGPL, SSPL or any license you list.

## What it does

- **Diff two SBOMs.** CycloneDX JSON or SPDX 2.x JSON, including one of each. Components are matched by package URL (purl) when there is one, otherwise by name, so a version bump shows up as *changed* rather than as one removal plus one addition. Several versions of the same package are tracked separately. License-only and supplier changes are reported too.
- **Check licenses.** Presets: No GPL (includes AGPL), No AGPL, No Copyleft, No SSPL, Permissive Only, or your own list with `*` wildcards. SPDX license expressions are evaluated properly: `MIT OR GPL-2.0-only` passes "No GPL" because you can choose MIT, while `MIT AND GPL-3.0-only` fails. The check works on a single SBOM too.
- **Export.** Copy the diff as Markdown for a pull request or release notes, or download the full result as JSON.
- **Private by construction.** Files are read with the browser's FileReader and never leave the page. The Content Security Policy blocks connections to any other origin, so the page cannot send your SBOM anywhere even by mistake.

## Limitations

- JSON only. CycloneDX XML and SPDX tag-value are not read.
- SPDX 3.0 (JSON-LD) is not supported yet; you get a clear message instead of a wrong result.
- No vulnerability data. This tool tells you what changed, not which changes are vulnerable.
- Files up to 20 MB.

## Run it locally

```bash
npm ci
npm run build     # compiles core.ts and app.ts to JavaScript
npm start         # http://localhost:8080
```

The page is static: after `npm run build` you can also open `index.html` from disk. Opening it from disk disables only the "Load samples" buttons, since browsers block local file fetches.

## Tests

```bash
npm test           # logic tests: the test pack plus regression cases (Node, no browser)
npm run test:e2e   # browser tests against the real page (needs `npx playwright install chromium`, or Google Chrome)
npm run test:all   # both, as CI runs them
```

[`test/fixtures/`](test/fixtures/) holds the test SBOMs, and [`test/expected.json`](test/expected.json) the hand-written expected result for each.

## How it is built

| File | Role |
|---|---|
| `core.ts` | Format detection, normalization, license expression parsing, diff, policy, reports. No DOM. |
| `app.ts` | The page: file loading, rendering, export. |
| `index.html` | Markup and styles; loads `core.js` then `app.js`. |
| `*-*.html` | Guides: generating SBOMs, CycloneDX vs SPDX, license policies. |
| `samples/` | Example SBOMs behind the "Load samples" buttons. |
| `test/` | Logic and browser tests, fixtures, expected results. |

There is no framework, bundler or runtime dependency. GitHub Actions runs the tests on every push and pull request, and deploys `main` to GitHub Pages when they pass.

## License

[MIT](LICENSE)
