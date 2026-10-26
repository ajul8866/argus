const LIVE_ROUTES = new Set([
  "dashboard",
  "projects",
  "audits",
  "tasks",
  "findings",
  "reports",
  "approvals",
]);

export function shouldRefreshOnReturn(route: string, overlayOpen: boolean): boolean {
  return !overlayOpen && LIVE_ROUTES.has(route);
}
