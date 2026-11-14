/**
 * C4/C2: scan page wiring. Bundled to dist/scan-ui.js (CSP script-src 'self'),
 * imports the pure audit bundle from ./scan.js. No network anywhere.
 */
import { scan, renderReport, summaryCounts } from "../dist/scan.js";

const $ = (id) => document.getElementById(id);
// Pending blobs for the download buttons; each scan replaces them and the
// listeners (registered once) always read the latest.
let auditBlob = null;
let reportBlob = null;
const save = (get, name) => {
  const blob = get();
  if (blob === null) return;
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.click();
};
$("download-audit").addEventListener("click", () => save(() => auditBlob, "audit.json"));
$("download-report").addEventListener("click", () => save(() => reportBlob, "report.html"));

const readFile = () =>
  new Promise((resolve) => {
    const f = $("file").files?.[0];
    if (!f) return resolve(null);
    const r = new FileReader();
    r.onload = () => resolve(String(r.result));
    r.readAsText(f);
  });

$("scan-btn").addEventListener("click", async () => {
  const text = (await readFile()) ?? $("input").value;
  const { result, gateError } = scan(text ?? "");
  $("output").hidden = false;
  if (gateError !== null || result === null) {
    $("gate").textContent = `Could not assess: ${gateError ?? "unknown"}`;
    $("counts").textContent = "";
    $("summary").textContent = "";
    return;
  }
  $("gate").textContent = "";
  $("counts").textContent = summaryCounts(result);
  $("summary").textContent = JSON.stringify(result, null, 2);
  auditBlob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
  reportBlob = new Blob([renderReport(result)], { type: "text/html" });
});
