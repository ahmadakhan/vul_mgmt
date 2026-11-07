import { createRoot } from 'react-dom/client';
import App from './App.tsx';
import { ErrorBoundary } from './components/ErrorBoundary.tsx';
import './index.css';

const PRELOAD_RETRY_KEY = 'vulnstream:preload-retry-at';
window.addEventListener('vite:preloadError', (event) => {
  event.preventDefault();
  try {
    const lastRetry = Number(sessionStorage.getItem(PRELOAD_RETRY_KEY) || 0);
    if (Date.now() - lastRetry < 30_000) return;
    sessionStorage.setItem(PRELOAD_RETRY_KEY, String(Date.now()));
    window.location.reload();
  } catch {
    // Keep the error boundary available if session storage is disabled.
  }
});
window.setTimeout(() => {
  try {
    sessionStorage.removeItem(PRELOAD_RETRY_KEY);
  } catch {
    // Storage can be disabled by browser policy.
  }
}, 30_000);

createRoot(document.getElementById('root')!).render(
  <ErrorBoundary>
    <App />
  </ErrorBoundary>,
);
