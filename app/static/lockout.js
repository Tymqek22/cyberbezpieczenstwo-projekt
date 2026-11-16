// Lockout countdown on the login page. The server enforces the lockout -
// this script only displays the remaining time and disables the button.
(function () {
  const box = document.getElementById("lockout");
  if (!box) return;
  const label = document.getElementById("lockout-time");
  const button = document.getElementById("login-submit");
  const end = Date.now() + parseInt(box.dataset.remaining, 10) * 1000;

  function tick() {
    const left = Math.max(0, Math.round((end - Date.now()) / 1000));
    const mm = String(Math.floor(left / 60)).padStart(2, "0");
    const ss = String(left % 60).padStart(2, "0");
    label.textContent = mm + ":" + ss;
    if (left === 0) {
      box.className = "alert info";
      box.textContent = "Blokada wygasła. Możesz spróbować zalogować się ponownie.";
      if (button) button.disabled = false;
      return;
    }
    if (button) button.disabled = true;
    setTimeout(tick, 1000);
  }
  tick();
})();
