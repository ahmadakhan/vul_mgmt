import type { ButtonHTMLAttributes, ReactNode } from 'react';

export interface SecondaryButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  icon?: ReactNode;
  loading?: boolean;
}

export function SecondaryButton({
  children,
  icon,
  loading = false,
  disabled,
  className = '',
  ...rest
}: SecondaryButtonProps) {
  return (
    <button
      disabled={disabled || loading}
      className={[
        'inline-flex items-center gap-2 rounded-xl border border-zinc-700 bg-zinc-900 px-3.5 py-2.5 text-xs font-medium text-zinc-200 transition hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-60 light:border-zinc-300 light:bg-white light:text-zinc-800 light:hover:bg-zinc-100',
        className,
      ].join(' ')}
      {...rest}
    >
      {icon}
      <span>{children}</span>
    </button>
  );
}
