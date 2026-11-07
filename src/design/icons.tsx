import type { ComponentPropsWithoutRef } from 'react';

export const DashboardIcon = ({
	size = 16,
	strokeWidth,
	className,
	style,
	...props
}: ComponentPropsWithoutRef<'img'> & { size?: number; strokeWidth?: number }) => (
	<img
		src="/favicon.ico"
		alt=""
		width={size}
		height={size}
		className={className}
		style={style}
		{...props}
	/>
);
