export function niceTicks(maxValue: number, count = 5): number[] {
  if (!Number.isFinite(maxValue) || maxValue <= 0) return [0];
  const niceNum = (value: number, round: boolean): number => {
    const exponent = Math.floor(Math.log10(value));
    const fraction = value / 10 ** exponent;
    const rounded = round
      ? fraction < 1.5
        ? 1
        : fraction < 3
          ? 2
          : fraction < 7
            ? 5
            : 10
      : fraction <= 1
        ? 1
        : fraction <= 2
          ? 2
          : fraction <= 5
            ? 5
            : 10;
    return rounded * 10 ** exponent;
  };

  const range = niceNum(maxValue, false);
  const step = niceNum(range / Math.max(count - 1, 1), true);
  const precision = Math.max(0, Math.ceil(-Math.log10(step)));
  const factor = 10 ** precision;
  const stop = Math.ceil(maxValue / step) * step;
  const ticks: number[] = [];
  for (let value = 0; value <= stop + step * 0.5; value += step) {
    const tick = Math.round(value * factor) / factor;
    if (ticks[ticks.length - 1] !== tick) ticks.push(tick);
  }
  const finalTick = Math.round(stop * factor) / factor;
  if (ticks.length === 0) ticks.push(0);
  if (ticks[ticks.length - 1] < maxValue && ticks[ticks.length - 1] !== finalTick) ticks.push(finalTick);
  return ticks;
}