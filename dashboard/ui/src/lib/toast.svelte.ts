/* Minimal toast notifications (replaces alert()). */
import { SvelteMap } from 'svelte/reactivity';
import type { ToastKind } from './types';

export const toasts = new SvelteMap<number, { message: string; kind: ToastKind }>();

let seq = 0;

export function toast(message: string, kind: ToastKind = 'info', ttl = 4000): void {
  const id = ++seq;
  toasts.set(id, { message, kind });
  setTimeout(() => toasts.delete(id), ttl);
}
