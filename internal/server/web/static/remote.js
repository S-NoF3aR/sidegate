/* SPDX-License-Identifier: AGPL-3.0-only */
import Guacamole from "./vendor/guacamole-common-1.5.0.min.js";

const $ = (id) => document.getElementById(id);
const root = $("rdp");
const screen = $("screen");
const overlay = $("overlay");
const message = $("message");
const form = $("credentials");
const actions = $("actions");
const status = $("status");
const ssh = root.dataset.protocol === "ssh";
// Ctrl+Alt+Del only exists for remote desktops.
const noop = { disabled: true };
const buttons = { cad: $("cad") || noop, disconnect: $("disconnect") };

let client = null;
let lastError = "";

function setStatus(text) {
  status.textContent = text;
}

function showMessage(title, text, withActions) {
  message.replaceChildren();
  const h = document.createElement("h1");
  h.textContent = title;
  message.append(h);
  if (text) {
    const p = document.createElement("p");
    p.className = "muted";
    p.textContent = text;
    message.append(p);
  }
  message.hidden = false;
  form.hidden = true;
  actions.hidden = !withActions;
  overlay.hidden = false;
}

const overlayOpen = () => !overlay.hidden;

// Scale the remote display to the window, keeping its aspect ratio.
function fit() {
  if (!client) return;
  const display = client.getDisplay();
  const w = display.getWidth(), h = display.getHeight();
  if (!w || !h) return;
  display.scale(Math.min(screen.clientWidth / w, screen.clientHeight / h));
}

// The remote desktop follows the browser window's size.
let resizeTimer;
window.addEventListener("resize", () => {
  fit();
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => client && client.sendSize(screen.clientWidth, screen.clientHeight), 300);
});

// The remote computer asks for credentials (e.g. with NLA).
function askCredentials(params) {
  for (const label of form.querySelectorAll("label[data-param]")) {
    label.hidden = !params.includes(label.dataset.param);
  }
  const user = form.elements.username;
  if (!user.value) {
    // SSH accounts are usually the local part of the sign-in name.
    const name = root.dataset.username || "";
    user.value = ssh ? name.split("@")[0] : name;
  }
  message.hidden = true;
  actions.hidden = true;
  form.hidden = false;
  overlay.hidden = false;
  form.onsubmit = (e) => {
    e.preventDefault();
    for (const name of params) {
      const field = form.elements[name];
      const stream = client.createArgumentValueStream("text/plain", name);
      const writer = new Guacamole.StringWriter(stream);
      writer.sendText(field ? field.value : "");
      writer.sendEnd();
    }
    form.elements.password.value = "";
    showMessage("Connecting…", "Signing in to the remote computer.");
  };
  (params.includes("username") && !user.value ? user : form.elements.password).focus();
}

function connect() {
  lastError = "";
  screen.replaceChildren();
  showMessage("Connecting…", ssh ? "Opening a terminal session." : "Opening a remote desktop session.");
  setStatus("Connecting…");

  client = new Guacamole.Client(new Guacamole.WebSocketTunnel("/.sidegate/guac"));
  const display = client.getDisplay();
  screen.append(display.getElement());
  display.onresize = fit;

  client.onerror = (st) => { lastError = st.message || "The connection failed."; };
  client.onrequired = askCredentials;
  client.onstatechange = (state) => {
    switch (state) {
      case Guacamole.Client.State.CONNECTED:
        overlay.hidden = true;
        setStatus("Connected");
        buttons.cad.disabled = buttons.disconnect.disabled = false;
        fit();
        screen.focus();
        break;
      case Guacamole.Client.State.DISCONNECTED:
        buttons.cad.disabled = buttons.disconnect.disabled = true;
        setStatus("Disconnected");
        showMessage("Disconnected", lastError || "The session ended.", true);
        client = null;
        break;
    }
  };

  // Remote clipboard → local clipboard (best effort; browsers may refuse).
  client.onclipboard = (stream, mimetype) => {
    if (!/^text\//.test(mimetype)) return;
    const reader = new Guacamole.StringReader(stream);
    let text = "";
    reader.ontext = (t) => { text += t; };
    reader.onend = () => navigator.clipboard?.writeText(text).catch(() => {});
  };

  const mouse = new Guacamole.Mouse(display.getElement());
  mouse.onEach(["mousedown", "mousemove", "mouseup"], (e) => client && client.sendMouseState(e.state, true));
  const touch = new Guacamole.Mouse.Touchscreen(display.getElement());
  touch.onEach(["mousedown", "mousemove", "mouseup"], (e) => client && client.sendMouseState(e.state, true));

  const params = new URLSearchParams({
    width: screen.clientWidth,
    height: screen.clientHeight,
    dpi: 96,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "",
  });
  client.connect(params.toString());
}

// Local clipboard → remote, when the window regains focus.
window.addEventListener("focus", () => {
  if (!client || !navigator.clipboard?.readText) return;
  navigator.clipboard.readText().then((text) => {
    if (!client || !text) return;
    const writer = new Guacamole.StringWriter(client.createClipboardStream("text/plain"));
    writer.sendText(text);
    writer.sendEnd();
  }).catch(() => {});
});

// Keys go to the remote desktop unless the overlay (e.g. the credentials
// form) is open.
const keyboard = new Guacamole.Keyboard(document);
keyboard.onkeydown = (keysym) => {
  if (!client || overlayOpen()) return true;
  client.sendKeyEvent(1, keysym);
  return false;
};
keyboard.onkeyup = (keysym) => {
  if (client && !overlayOpen()) client.sendKeyEvent(0, keysym);
};

buttons.cad.onclick = () => {
  const keys = [0xffe3, 0xffe9, 0xffff]; // Control_L, Alt_L, Delete
  keys.forEach((k) => client.sendKeyEvent(1, k));
  keys.reverse().forEach((k) => client.sendKeyEvent(0, k));
  screen.focus();
};
buttons.disconnect.onclick = () => client && client.disconnect();
$("reconnect").onclick = connect;
$("fullscreen").onclick = () => {
  if (document.fullscreenElement) document.exitFullscreen();
  else root.requestFullscreen?.().then(fit, () => {});
};
window.addEventListener("pagehide", () => client && client.disconnect());

if (root.dataset.browser === "true") {
  connect();
} else {
  setStatus("Unavailable");
  showMessage("Browser access is not enabled",
    "This proxy has no remote access service (guacd) configured. Connect with your own client using the Sidegate CLI instead.", false);
}
