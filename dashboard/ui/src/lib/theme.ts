/* Light/dark mode. Persisted in localStorage and applied as the `dark` class
   on <html>. Defaults to dark. */
const KEY = 'theme';

export function initTheme(): void {
  const saved = localStorage.getItem(KEY);
  const dark = saved ? saved === 'dark' : true;
  document.documentElement.classList.toggle('dark', dark);
}

export function isDark(): boolean {
  return document.documentElement.classList.contains('dark');
}

export function toggleTheme(): boolean {
  const dark = !isDark();
  document.documentElement.classList.toggle('dark', dark);
  localStorage.setItem(KEY, dark ? 'dark' : 'light');
  return dark;
}
