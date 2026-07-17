/* Promise-based confirm/prompt, rendered by <Dialog/> mounted once in App. */

type DialogKind = 'confirm' | 'prompt';

interface DialogState {
  open: boolean;
  kind: DialogKind;
  title: string;
  message: string;
  value: string;
  placeholder: string;
  okLabel: string;
  danger: boolean;
  resolve: ((result: boolean | string | null) => void) | null;
}

export const dialog: DialogState = $state({
  open: false,
  kind: 'confirm',
  title: '',
  message: '',
  value: '',
  placeholder: '',
  okLabel: 'Confirm',
  danger: false,
  resolve: null,
});

interface OpenOpts {
  title?: string;
  message?: string;
  value?: string;
  placeholder?: string;
  okLabel?: string;
  danger?: boolean;
}

function open(kind: DialogKind, opts: OpenOpts): Promise<boolean | string | null> {
  return new Promise((resolve) => {
    Object.assign(dialog, {
      open: true,
      kind,
      title: '',
      message: '',
      value: '',
      placeholder: '',
      okLabel: kind === 'prompt' ? 'Save' : 'Confirm',
      danger: false,
      ...opts,
      resolve,
    });
  });
}

export function confirm(opts: OpenOpts): Promise<boolean> {
  return open('confirm', opts) as Promise<boolean>;
}

export function prompt(opts: OpenOpts): Promise<string | null> {
  return open('prompt', opts) as Promise<string | null>;
}

export function settle(result: boolean | string | null): void {
  const r = dialog.resolve;
  dialog.open = false;
  dialog.resolve = null;
  if (r) r(result);
}
