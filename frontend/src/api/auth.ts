let memoryApiKey: string | null = null;
const API_KEY_SESSION_STORAGE_KEY = 'sentinel_api_key';

type UnauthorizedListener = () => void;
const unauthorizedListeners: Set<UnauthorizedListener> = new Set();

export function getApiKey(): string | null {
  if (memoryApiKey) {
    return memoryApiKey;
  }
  try {
    const stored = sessionStorage.getItem(API_KEY_SESSION_STORAGE_KEY);
    if (stored) {
      memoryApiKey = stored;
      return stored;
    }
  } catch {
    // sessionStorage unavailable
  }
  return null;
}

export function setApiKey(key: string | null): void {
  memoryApiKey = key;
  try {
    if (key) {
      sessionStorage.setItem(API_KEY_SESSION_STORAGE_KEY, key);
    } else {
      sessionStorage.removeItem(API_KEY_SESSION_STORAGE_KEY);
    }
  } catch {
    // sessionStorage unavailable
  }
}

export function clearApiKey(): void {
  setApiKey(null);
}

export function subscribeToUnauthorized(listener: UnauthorizedListener): () => void {
  unauthorizedListeners.add(listener);
  return () => {
    unauthorizedListeners.delete(listener);
  };
}

export function notifyUnauthorized(): void {
  unauthorizedListeners.forEach((fn) => {
    try {
      fn();
    } catch {
      // ignore
    }
  });
}
