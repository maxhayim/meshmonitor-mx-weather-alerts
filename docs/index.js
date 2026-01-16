// Display-only script loader for GitHub Pages
// It fetches the runtime file from the repo root and prints it into <pre>.

(async () => {
  const pre = document.getElementById("code");
  const url = "../mm_wx.py";

  try {
    const res = await fetch(url, { cache: "no-store" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const txt = await res.text();
    pre.textContent = txt;
  } catch (err) {
    pre.textContent =
      "Failed to load mm_wx.py\n\n" +
      String(err) +
      "\n\nIf you are viewing this locally, serve the docs folder with a simple web server.";
  }
})();
