(() => {
  const CODE_EL = document.getElementById("code");
  const COPY_BTN = document.getElementById("copyBtn");

  // Fetch raw mm_wx.py from main for display purposes.
  // (For pinned releases, change /main/ to /vX.Y.Z/.)
  const RAW_URL = "https://raw.githubusercontent.com/maxhayim/meshmonitor-mx-weather-alerts/main/mm_wx.py";

  async function load() {
    try {
      const resp = await fetch(RAW_URL, { cache: "no-store" });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const text = await resp.text();
      CODE_EL.textContent = text;

      COPY_BTN.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(text);
          COPY_BTN.textContent = "Copied";
          setTimeout(() => (COPY_BTN.textContent = "Copy"), 1200);
        } catch {
          COPY_BTN.textContent = "Copy failed";
          setTimeout(() => (COPY_BTN.textContent = "Copy"), 1200);
        }
      });
    } catch (e) {
      CODE_EL.textContent = `Failed to load script from:\n${RAW_URL}\n\nError: ${String(e)}`;
    }
  }

  load();
})();
