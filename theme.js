// Applied before first paint to avoid a flash of the wrong theme: an explicit
// localStorage preference wins, else the OS setting.
//
// A classic (non-module) external script in <head> is fetched and executed
// synchronously, so this still runs before the body is parsed -- the property
// that made it inline in the first place. It lives in its own file so the
// page's Content-Security-Policy can be `script-src 'self'` with no
// 'unsafe-inline': the one inline script was the only reason that escape hatch
// had to stay open, and leaving it open would also have permitted inline event
// handlers, which is the realistic XSS shape here (file names reach the
// results table, and a dropped file's name is attacker-chosen).
(function () {
  var saved = null;
  try {
    saved = localStorage.getItem("devguard-scan-theme");
  } catch (e) {
    /* storage disabled (private browsing, etc.) */
  }
  var theme = saved || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
  document.documentElement.dataset.theme = theme;
})();
