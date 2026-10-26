import { api } from "../api.ts";

export async function createProjectWithSnapshot(body: Record<string, unknown>): Promise<{ id: string; importError: string | null }> {
  const { project } = await api<{ project: { id: string } }>("/api/projects", { method: "POST", body });
  try {
    await api(`/api/projects/${project.id}/import`, { method: "POST", body: {} });
    return { id: project.id, importError: null };
  } catch (error) {
    return { id: project.id, importError: error instanceof Error ? error.message : "Unable to import files" };
  }
}

export async function createAuditWithSnapshot(input: {
  projectId: string;
  repositoryId?: string;
  overrides?: Record<string, unknown>;
  startNow: boolean;
}): Promise<{ id: string; startError: string | null }> {
  let repositoryId = input.repositoryId;
  if (!repositoryId) {
    const { repository } = await api<{ repository: { id: string } }>(`/api/projects/${input.projectId}/import`, { method: "POST", body: {} });
    repositoryId = repository.id;
  }
  const { audit } = await api<{ audit: { id: string } }>("/api/audits", {
    method: "POST", body: { project_id: input.projectId, repository_id: repositoryId, overrides: input.overrides ?? {} },
  });
  if (input.startNow) {
    try {
      await api(`/api/audits/${audit.id}/start`, { method: "POST" });
    } catch (error) {
      return { id: audit.id, startError: error instanceof Error ? error.message : "Unable to start audit" };
    }
  }
  return { id: audit.id, startError: null };
}
