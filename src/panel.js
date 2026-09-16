/* Curfew web panel — the only script the panel loads.
 *
 * Deliberately tiny and optional: every action works as a plain form POST
 * without this file, so the panel still functions if scripting is blocked.
 * This only adds two conveniences — a confirmation on destructive buttons,
 * and keeping the device list fresh. */

(function () {
  "use strict";

  // Confirm anything marked destructive, so a mis-tap on a phone can't cut a
  // device off.
  document.addEventListener("click", function (event) {
    var button = event.target.closest("button[data-confirm]");
    if (button && !window.confirm(button.getAttribute("data-confirm"))) {
      event.preventDefault();
    }
  });

  // Refresh periodically, but never while the owner is typing or has made
  // selections — reloading then would lose their input.
  var REFRESH_MS = 15000;

  function busyTyping() {
    var active = document.activeElement;
    if (!active) return false;
    var tag = active.tagName;
    return tag === "INPUT" || tag === "SELECT" || tag === "TEXTAREA" || tag === "BUTTON";
  }

  window.setInterval(function () {
    if (document.hidden || busyTyping()) return;
    window.location.reload();
  }, REFRESH_MS);

  // Don't queue a reload for a page the browser restored from the back/forward
  // cache; it would show a stale view.
  window.addEventListener("pageshow", function (event) {
    if (event.persisted) window.location.reload();
  });
})();
