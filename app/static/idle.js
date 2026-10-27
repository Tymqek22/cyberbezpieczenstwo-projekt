// Automatic logout after inactivity (UX layer).
// The actual limit is enforced by the server - any request after the timeout ends the session.
(function () {
  const minutes = parseInt(document.body.dataset.idleMinutes, 10);
  if (!minutes) return;
  const deadline = Date.now() + minutes * 60 * 1000 + 2000;
  const counter = document.getElementById("idle-counter");

  function tick() {
    const left = Math.max(0, deadline - Date.now());
    if (counter) {
      const s = Math.ceil(left / 1000);
      counter.textContent = "⏱ " + Math.floor(s / 60) + ":" + String(s % 60).padStart(2, "0");
    }
    if (left === 0) {
      window.location.href = "/session/expired";
      return;
    }
    setTimeout(tick, 1000);
  }
  tick();
})();
