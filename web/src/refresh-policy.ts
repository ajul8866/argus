const LIVE_ROUTES = new Set([
  "dashboard",
  "projects",
  "audits",
  "tasks",
  "findings",
  "reports",
  "approvals",
]);

function isLiveRoute(route: string): boolean {
  return LIVE_ROUTES.has(route);
}

export function shouldRefreshOnReturn(route: string, overlayOpen: boolean): boolean {
  return !overlayOpen && isLiveRoute(route);
}

/** A live route skipped a refresh because a dialog or drawer was open. Replay it on close. */
export function shouldDeferRefresh(route: string, overlayOpen: boolean): boolean {
  return overlayOpen && isLiveRoute(route);
}
