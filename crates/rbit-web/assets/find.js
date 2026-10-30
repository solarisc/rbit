// "Go to file" on the code page: matching files appear under the box as you type, the
// arrow keys move through them, Enter opens one, and `t` focuses the box from anywhere on
// the page. Without this file the box is a plain GET form for the finder page.
const requests = new WeakMap();

const menuOf = input => input.closest('[data-file-finder]')?.querySelector('[data-find-menu]');
const options = menu => [...menu.querySelectorAll('[data-find-option]')];

function close(input) {
  const menu = menuOf(input);
  if (!menu) return;
  menu.hidden = true;
  input.setAttribute('aria-expanded', 'false');
  input.removeAttribute('aria-activedescendant');
}

function select(input, index) {
  const menu = menuOf(input);
  const rows = options(menu);
  if (!rows.length) return;
  const next = (index + rows.length) % rows.length;
  for (const [i, row] of rows.entries()) {
    row.id ||= `file-finder-option-${i}`;
    row.setAttribute('aria-selected', String(i === next));
  }
  input.setAttribute('aria-activedescendant', rows[next].id);
  rows[next].scrollIntoView({ block: 'nearest' });
}

async function search(input) {
  requests.get(input)?.abort();
  const controller = new AbortController();
  requests.set(input, controller);
  const url = new URL(input.dataset.findUrl, location.href);
  url.searchParams.set('q', input.value);
  url.searchParams.set('fragment', 'true');
  try {
    const response = await fetch(url, { signal: controller.signal });
    if (!response.ok) throw new Error('search failed');
    const html = await response.text();
    if (controller.signal.aborted || document.activeElement !== input) return;
    const menu = menuOf(input);
    const found = new DOMParser().parseFromString(html, 'text/html').querySelector('[data-find-results]');
    if (!menu || !found) return;
    menu.replaceChildren(document.importNode(found, true));
    menu.hidden = false;
    input.setAttribute('aria-expanded', 'true');
    input.removeAttribute('aria-activedescendant');
    if (input.value.trim()) select(input, 0);
  } catch (error) {
    if (error.name !== 'AbortError') close(input);
  }
}

const timers = new WeakMap();
function schedule(input, delay) {
  clearTimeout(timers.get(input));
  timers.set(input, setTimeout(() => search(input), delay));
}

document.addEventListener('input', event => {
  if (event.target.matches?.('[data-find-input]')) schedule(event.target, 120);
});

document.addEventListener('focusin', event => {
  if (event.target.matches?.('[data-find-input]')) schedule(event.target, 0);
});

document.addEventListener('focusout', event => {
  const finder = event.target.closest?.('[data-file-finder]');
  if (finder && !finder.contains(event.relatedTarget)) close(finder.querySelector('[data-find-input]'));
});

document.addEventListener('keydown', event => {
  const input = event.target;
  if (input.matches?.('[data-find-input]')) {
    const menu = menuOf(input);
    if (event.key === 'Escape') {
      close(input);
      input.blur();
      return;
    }
    if (!menu || menu.hidden) return;
    const rows = options(menu);
    const current = rows.findIndex(row => row.getAttribute('aria-selected') === 'true');
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      select(input, current + (event.key === 'ArrowDown' ? 1 : -1));
    } else if (event.key === 'Enter' && current >= 0) {
      event.preventDefault();
      rows[current].click();
    }
    return;
  }
  // `t` jumps to the finder, as on GitHub, unless the visitor is typing somewhere.
  if (event.key !== 't' || event.ctrlKey || event.metaKey || event.altKey || event.defaultPrevented) return;
  if (input.closest?.('input, textarea, select, [contenteditable=""], [contenteditable="true"]')) return;
  const finder = document.querySelector('[data-find-input]');
  if (!finder || !finder.offsetParent) return;
  event.preventDefault();
  finder.focus();
});

document.addEventListener('htmx:beforeSwap', () => {
  for (const input of document.querySelectorAll('[data-find-input]')) {
    requests.get(input)?.abort();
    clearTimeout(timers.get(input));
  }
});
