/** Sons CRT sintetizados via Web Audio API (sem arquivos externos). */

import { SOUND_STORAGE_KEY } from "./constants.js";

let audioCtx = null;
let enabled = null;
let updateSoundButton = null;

function prefersQuiet() {
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function loadEnabled() {
  if (enabled !== null) return enabled;
  try {
    const raw = localStorage.getItem(SOUND_STORAGE_KEY);
    enabled = raw === null ? true : raw === "1";
  } catch {
    enabled = true;
  }
  return enabled;
}

function getCtx() {
  if (!audioCtx) {
    const Ctx = window.AudioContext || window.webkitAudioContext;
    if (!Ctx) return null;
    audioCtx = new Ctx();
  }
  return audioCtx;
}

async function ensureCtx() {
  const ctx = getCtx();
  if (!ctx) return null;
  if (ctx.state === "suspended") {
    try {
      await ctx.resume();
    } catch {
      return null;
    }
  }
  return ctx;
}

function tone(ctx, {
  type = "sine",
  freq = 440,
  freqEnd = null,
  duration = 0.1,
  volume = 0.02,
  delay = 0,
}) {
  const osc = ctx.createOscillator();
  const gain = ctx.createGain();
  const t = ctx.currentTime + delay;

  osc.type = type;
  osc.frequency.setValueAtTime(freq, t);
  if (typeof freqEnd === "number") {
    osc.frequency.linearRampToValueAtTime(freqEnd, t + duration);
  }

  gain.gain.setValueAtTime(Math.max(volume, 0.0001), t);
  gain.gain.exponentialRampToValueAtTime(0.0001, t + duration);

  osc.connect(gain);
  gain.connect(ctx.destination);
  osc.start(t);
  osc.stop(t + duration + 0.03);
}

function playPattern(ctx, type) {
  switch (type) {
    case "send":
      tone(ctx, { type: "sine", freq: 880, duration: 0.04, volume: 0.012 });
      break;
    case "success":
      tone(ctx, { type: "square", freq: 520, duration: 0.07, volume: 0.014 });
      tone(ctx, { type: "square", freq: 780, duration: 0.09, volume: 0.014, delay: 0.07 });
      tone(ctx, { type: "square", freq: 1040, duration: 0.12, volume: 0.012, delay: 0.15 });
      break;
    case "error":
      tone(ctx, { type: "sawtooth", freq: 220, freqEnd: 140, duration: 0.22, volume: 0.018 });
      break;
    case "warn":
      tone(ctx, { type: "triangle", freq: 440, duration: 0.08, volume: 0.014 });
      tone(ctx, { type: "triangle", freq: 330, duration: 0.1, volume: 0.012, delay: 0.09 });
      break;
    case "exec_ok":
      tone(ctx, { type: "square", freq: 600, duration: 0.05, volume: 0.011 });
      tone(ctx, { type: "square", freq: 900, duration: 0.07, volume: 0.01, delay: 0.05 });
      break;
    case "exec_fail":
      tone(ctx, { type: "sawtooth", freq: 280, freqEnd: 180, duration: 0.14, volume: 0.014 });
      break;
    case "exec_blocked":
      tone(ctx, { type: "triangle", freq: 200, duration: 0.06, volume: 0.012 });
      tone(ctx, { type: "triangle", freq: 160, duration: 0.08, volume: 0.01, delay: 0.07 });
      break;
    case "panel":
      tone(ctx, { type: "sine", freq: 640, duration: 0.03, volume: 0.008 });
      break;
    case "toggle":
      tone(ctx, { type: "sine", freq: 720, duration: 0.05, volume: 0.01 });
      break;
    case "boot":
      tone(ctx, { type: "square", freq: 440, duration: 0.06, volume: 0.01 });
      tone(ctx, { type: "square", freq: 660, duration: 0.08, volume: 0.009, delay: 0.07 });
      break;
    default:
      break;
  }
}

export function initAudio() {
  loadEnabled();
  const unlock = () => { ensureCtx(); };
  document.addEventListener("pointerdown", unlock, { once: true, passive: true });
  document.addEventListener("keydown", unlock, { once: true });
}

export function isSoundEnabled() {
  return loadEnabled();
}

export function setSoundEnabled(on) {
  enabled = !!on;
  try {
    localStorage.setItem(SOUND_STORAGE_KEY, enabled ? "1" : "0");
  } catch { /* ignore */ }
  updateSoundButton?.();
}

export function toggleSound() {
  const next = !isSoundEnabled();
  setSoundEnabled(next);
  if (next) playSound("toggle");
  return next;
}

export function bindSoundButton(btn) {
  if (!btn) return;
  const refresh = () => {
    const on = isSoundEnabled();
    btn.textContent = on ? "Som: ligado" : "Som: mudo";
    btn.classList.toggle("sound-off", !on);
    btn.title = on ? "Desativar sons" : "Ativar sons";
  };
  updateSoundButton = refresh;
  refresh();
  btn.addEventListener("click", (e) => {
    e.stopPropagation();
    toggleSound();
    refresh();
  });
}

export function playSound(type) {
  if (!loadEnabled() || prefersQuiet() || !type) return;
  ensureCtx().then((ctx) => {
    if (ctx) playPattern(ctx, type);
  });
}
