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
  mode?: "static" | "dynamic" | "hybrid";
  targetId?: string;
}): Promise<{ id: string; startError: string | null }> {
  const mode = input.mode ?? "static";
  let repositoryId = input.repositoryId;
  // A dynamic audit may run without a repository; static and hybrid may not.
  if (!repositoryId && mode !== "dynamic") {
    const { repository } = await api<{ repository: { id: string } }>(`/api/projects/${input.projectId}/import`, { method: "POST", body: {} });
    repositoryId = repository.id;
  }
  if (mode !== "static" && !input.targetId) {
    throw new Error("A dynamic or hybrid audit needs an authorized target");
  }
  const { audit } = await api<{ audit: { id: string } }>("/api/audits", {
    method: "POST",
    body: {
      project_id: input.projectId,
      ...(repositoryId ? { repository_id: repositoryId } : {}),
      overrides: input.overrides ?? {},
      ...(mode !== "static" ? { mode } : {}),
      ...(input.targetId ? { target_id: input.targetId } : {}),
    },
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
