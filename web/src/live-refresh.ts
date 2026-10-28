import { shouldDeferRefresh, shouldRefreshOnReturn } from "./refresh-policy.ts";

export const LIVE_REFRESH_DEBOUNCE_MS = 1_100;

type Cancel = { cancel: () => void };

export type LiveRefresh = {
  /** Coalesce an SSE (or similar) signal into one refresh. */
  request(): void;
  /** The tab became visible. */
  onVisible(): void;
  /**
   * The last dialog or drawer closed.
   * Returns true when a deferred live refresh starts.
   */
  onOverlaysClosed(): boolean;
  /** A route render already fetched current data, so a deferred catch-up is redundant. */
  onRendered(): void;
  dispose(): void;
};

/**
 * Coalesce live signals without postponing updates under a continuous event stream.
 * An open dialog or drawer holds the render until the last overlay closes.
 */
export function createLiveRefresh(deps: {
  getRoute: () => string;
  isOverlayOpen: () => boolean;
  isVisible: () => boolean;
  isActive: () => boolean;
  render: () => void | Promise<void>;
  schedule?: (run: () => void, delayMs: number) => Cancel;
}): LiveRefresh {
  let pending = false;
  let timer: Cancel | null = null;
  let rendering = false;
  const schedule = deps.schedule ?? ((run: () => void, delayMs: number): Cancel => {
    const id = setTimeout(run, delayMs);
    return { cancel: () => clearTimeout(id) };
  });

  function clearTimer(): void {
    timer?.cancel();
    timer = null;
  }

  function finishRender(): void {
    rendering = false;
    if (pending) refresh.request();
  }

  function renderNow(): boolean {
    if (!deps.isActive()) return false;
    if (rendering) {
      pending = true;
      return false;
    }
    pending = false;
    clearTimer();
    rendering = true;
    try {
      const completion = deps.render();
      if (completion) void completion.then(finishRender, finishRender);
      else finishRender();
    } catch (error) {
      finishRender();
      throw error;
    }
    return true;
  }

  const refresh: LiveRefresh = {
    request() {
      if (!deps.isActive()) return;
      const route = deps.getRoute();
      if (shouldDeferRefresh(route, deps.isOverlayOpen())) {
        pending = true;
        clearTimer();
        return;
      }
      if (!shouldRefreshOnReturn(route, false)) return;
      pending = true;
      if (timer || rendering) return;
      timer = schedule(() => {
        timer = null;
        const current = deps.getRoute();
        if (shouldDeferRefresh(current, deps.isOverlayOpen())) {
          pending = true;
          return;
        }
        if (!deps.isVisible() || !shouldRefreshOnReturn(current, false)) return;
        renderNow();
      }, LIVE_REFRESH_DEBOUNCE_MS);
    },

    onVisible() {
      if (!deps.isActive() || !deps.isVisible()) return;
      const route = deps.getRoute();
      const overlayOpen = deps.isOverlayOpen();
      if (shouldRefreshOnReturn(route, overlayOpen)) {
        renderNow();
        return;
      }
      if (shouldDeferRefresh(route, overlayOpen)) {
        pending = true;
        clearTimer();
      }
    },

    onOverlaysClosed() {
      if (!pending) return false;
      if (!deps.isActive()) {
        pending = false;
        return false;
      }
      if (deps.isOverlayOpen()) return false;
      if (!shouldRefreshOnReturn(deps.getRoute(), false)) {
        pending = false;
        return false;
      }
      if (!deps.isVisible()) return false;
      return renderNow();
    },

    onRendered() {
      pending = false;
      clearTimer();
    },

    dispose() {
      clearTimer();
      pending = false;
    },
  };
  return refresh;
}
