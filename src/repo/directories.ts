import { accessSync, constants, realpathSync, statSync } from "node:fs";
import { readdir, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, dirname, join, resolve, sep } from "node:path";
import { AppError, badRequest } from "../util.ts";
import { assertAuthorizedRoot } from "./workspace.ts";

export type RepositoryFolders = {
  path: string;
  parent_path: string | null;
  roots: Array<{ name: string; path: string }>;
  folders: Array<{ name: string; path: string; is_repository: boolean }>;
  next_offset: number | null;
};

export function detectRepositoryRoots(candidates: string[]): string[] {
  const roots = new Set<string>();
  for (const candidate of candidates) {
    try {
      const path = realpathSync(candidate);
      if (!statSync(path).isDirectory()) continue;
      accessSync(path, constants.R_OK | constants.X_OK);
      roots.add(path);
    } catch {
      // Unavailable host locations are not offered in the folder picker.
    }
  }
  return [...roots];
}

function withinRoots(path: string, roots: string[]): boolean {
  return roots.some((root) => path === root || path.startsWith(root.endsWith(sep) ? root : `${root}${sep}`));
}

export async function listRepositoryFolders(
  allowedRoots: string[],
  options: { path?: string; search?: string; offset?: string } = {},
): Promise<RepositoryFolders> {
  if ((options.path?.length ?? 0) > 2_000 || options.path?.includes("\0")) throw badRequest("Invalid folder path");
  if ((options.search?.length ?? 0) > 200) throw badRequest("Folder search exceeds 200 characters");
  const offset = Number(options.offset ?? "0");
  if (!/^\d+$/.test(options.offset ?? "0") || !Number.isSafeInteger(offset)) throw badRequest("Invalid folder offset");
  const roots = detectRepositoryRoots(allowedRoots);
  const home = detectRepositoryRoots([homedir()])[0];
  const initial = home && withinRoots(home, roots) ? home : roots[0];
  if (!initial) throw new AppError(400, "folders_unavailable", "No readable repository folders were found on this host");
  const path = await assertAuthorizedRoot(resolve(options.path || initial), roots);
  let entries;
  try {
    entries = await readdir(path, { withFileTypes: true });
  } catch {
    throw new AppError(403, "folder_unreadable", "Argus cannot read this folder. Choose another folder.");
  }
  const search = (options.search ?? "").trim().toLowerCase();
  const directories = entries
    .filter((entry) => entry.isDirectory() && !entry.name.startsWith(".") && entry.name !== "node_modules" && entry.name.toLowerCase().includes(search))
    .sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
  const page = directories.slice(offset, offset + 100);
  const folders = await Promise.all(page.map(async (entry) => {
    const child = join(path, entry.name);
    const git = await stat(join(child, ".git")).catch(() => null);
    return { name: entry.name, path: child, is_repository: Boolean(git?.isDirectory() || git?.isFile()) };
  }));
  const parent = dirname(path);
  return {
    path,
    parent_path: parent !== path && withinRoots(parent, roots) ? parent : null,
    roots: roots.map((root) => ({ name: root === home ? "Home" : basename(root) || root, path: root })),
    folders,
    next_offset: offset + page.length < directories.length ? offset + page.length : null,
  };
}
