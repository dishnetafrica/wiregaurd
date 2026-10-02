// DishNet Web Desktop viewer. Uses Apache Guacamole's browser client
// (guacamole-common-js, Apache-2.0) over a WebSocket to this hub.
import Guacamole from './guacamole-common.min.js';

const display = document.getElementById('display');
const status = document.getElementById('status');
const overlay = document.getElementById('overlay');
const overlayMsg = document.getElementById('overlayMsg');
const ticket = display.dataset.ticket;

const proto = location.protocol === 'https:' ? 'wss://' : 'ws://';
const tunnel = new Guacamole.WebSocketTunnel(proto + location.host + '/desk/ws');
const client = new Guacamole.Client(tunnel);
const el = client.getDisplay().getElement();
display.appendChild(el);

function show(msg) { overlayMsg.textContent = msg; overlay.classList.remove('hidden'); }
function hide() { overlay.classList.add('hidden'); }

function size() { return { w: Math.max(640, display.clientWidth), h: Math.max(400, display.clientHeight) }; }

function fit() {
  const d = client.getDisplay();
  const s = size();
  const sw = s.w / Math.max(1, d.getWidth()), sh = s.h / Math.max(1, d.getHeight());
  d.scale(Math.min(sw, sh, 1));
}

client.onstatechange = (state) => {
  const names = { 0: 'Idle', 1: 'Connecting…', 2: 'Waiting for the office computer…', 3: 'Connected', 4: 'Disconnecting…', 5: 'Disconnected' };
  status.textContent = names[state] || '';
  if (state === 3) { hide(); display.focus(); }
  if (state === 5) show('Disconnected. Click Disconnect to go back, or reload the page to try again.');
};

tunnel.onerror = (err) => {
  const code = err && err.code;
  let msg = 'The connection to the office computer failed.';
  if (code === 0x0201 || code === 0x0202 || code === 0x0203) msg = 'The office computer did not answer. Is it switched on, with DishNet showing Connected and Remote Desktop allowed?';
  if (code === 0x0301 || code === 0x0303) msg = 'The office computer refused the Windows user name or password. Use the account that works on that computer itself.';
  if (code === 0x0308) msg = 'Your session timed out. Go back and open the office computer again.';
  show(msg + (err && err.message ? ' (' + err.message + ')' : ''));
};

client.onerror = (err) => show('Remote Desktop error: ' + (err && err.message ? err.message : 'unknown'));

// Mouse and keyboard
const mouse = new Guacamole.Mouse(el);
mouse.onmousedown = mouse.onmouseup = mouse.onmousemove = (state) => {
  const scale = client.getDisplay().getScale();
  client.sendMouseState(new Guacamole.Mouse.State(state.x / scale, state.y / scale, state.left, state.middle, state.right, state.up, state.down));
};
const touch = new Guacamole.Mouse.Touchscreen(el);
touch.onmousedown = touch.onmouseup = touch.onmousemove = mouse.onmousedown;
const keyboard = new Guacamole.Keyboard(document);
keyboard.onkeydown = (k) => client.sendKeyEvent(1, k);
keyboard.onkeyup = (k) => client.sendKeyEvent(0, k);

client.getDisplay().onresize = fit;
window.addEventListener('resize', () => { const s = size(); client.sendSize(s.w, s.h); fit(); });
document.getElementById('fit').addEventListener('click', fit);
document.getElementById('disconnect').addEventListener('click', () => { try { client.disconnect(); } catch (e) { /* ignore */ } });
window.addEventListener('beforeunload', () => { try { client.disconnect(); } catch (e) { /* ignore */ } });

const s0 = size();
show('Connecting to the office computer…');
client.connect('ticket=' + encodeURIComponent(ticket) + '&width=' + s0.w + '&height=' + s0.h + '&dpi=' + Math.round(96 * (window.devicePixelRatio || 1)));
