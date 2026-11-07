interface SystemUptime {
  uptime: string;
}

export const getSystemUptime = async (): Promise<SystemUptime> => {
  const response = await fetch('/api/system-uptime', {
    credentials: 'same-origin',
    headers: { 'content-type': 'application/json' },
    signal: AbortSignal.timeout(10000),
  });
  if (!response.ok) throw new Error(`Uptime request failed (HTTP ${response.status})`);
  const data: unknown = await response.json();
  if (!data || typeof data !== 'object' ||
    !('systemUptime' in data) || typeof data.systemUptime !== 'string' || !data.systemUptime)
    throw new Error('Invalid application uptime response');
  return { uptime: data.systemUptime };
};