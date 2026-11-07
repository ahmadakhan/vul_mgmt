interface ScopePreset {
  hours: number;
  label: string;
}

export const DEFAULT_INGESTION_WINDOW_HOURS = 24;

export const SCOPE_PRESETS: ScopePreset[] = [
  { hours: 6, label: '6 hours' },
  { hours: 12, label: '12 hours' },
  { hours: 24, label: '1 day' },
  { hours: 48, label: '2 days' },
  { hours: 72, label: '3 days' },
  { hours: 168, label: '1 week' },
  { hours: 336, label: '2 weeks' },
  { hours: 504, label: '3 weeks' },
  { hours: 672, label: '4 weeks' },
];

export function formatScopeLabel(hours: number): string {
  const preset = SCOPE_PRESETS.find((p) => p.hours === hours);
  return preset ? preset.label : `${hours} hours`;
}
