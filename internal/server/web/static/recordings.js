/* SPDX-License-Identifier: AGPL-3.0-only */
import Guacamole from "/static/vendor/guacamole-common-1.5.0.min.js";

const $ = (id) => document.getElementById(id);
const screen = $("player-screen");
const play = $("play");
const seek = $("seek");
const time = $("time");
const status = $("player-status");

// guacamole-common-js 1.5.0 can't play a Blob directly, so the recording
// is streamed through a static HTTP tunnel, as Guacamole's own player does.
const recording = new Guacamole.SessionRecording(new Guacamole.StaticHTTPTunnel($("player").dataset.src));
const display = recording.getDisplay();
screen.append(display.getElement());

const fmt = (ms) => {
  const s = Math.floor(ms / 1000);
  const h = Math.floor(s / 3600), m = Math.floor(s / 60) % 60, sec = String(s % 60).padStart(2, "0");
  return h ? `${h}:${String(m).padStart(2, "0")}:${sec}` : `${m}:${sec}`;
};
const showPosition = (pos) => {
  seek.value = pos;
  time.textContent = `${fmt(pos)} / ${fmt(recording.getDuration())}`;
};

function fit() {
  const w = display.getWidth(), h = display.getHeight();
  if (w && h) display.scale(Math.min(screen.clientWidth / w, 1));
}
display.onresize = fit;
window.addEventListener("resize", fit);

recording.onprogress = (duration) => {
  seek.max = duration;
  showPosition(recording.getPosition());
};
recording.onload = () => {
  status.textContent = "";
  play.disabled = seek.disabled = false;
  seek.max = recording.getDuration();
  showPosition(0);
};
recording.onerror = (message) => {
  status.textContent = "The recording could not be loaded: " + message;
};
recording.onplay = () => (play.textContent = "Pause");
recording.onpause = () => (play.textContent = "Play");
recording.onseek = (position) => showPosition(position);

play.addEventListener("click", () => (recording.isPlaying() ? recording.pause() : recording.play()));
seek.addEventListener("input", () => recording.seek(Number(seek.value)));
setInterval(() => recording.isPlaying() && showPosition(recording.getPosition()), 250);

recording.connect();
