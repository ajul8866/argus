import type { RepositoryFolders } from "../../../src/repo/directories.ts";
import { api } from "../api.ts";
import { button, emptyState, errorState, field, h, input, loading, modal, select } from "../ui.ts";

export function chooseRepositoryFolder(initialPath?: string): Promise<string | null> {
  return new Promise((resolve) => {
    let current: RepositoryFolders | null = null;
    let requestId = 0;
    let closed = false;
    let searchTimer: ReturnType<typeof setTimeout> | undefined;
    const locations = select("folder_location", []);
    const search = input("folder_search", { type: "search", placeholder: "Filter folders by name" });
    const address = input("folder_path", { placeholder: "Or paste a folder path" });
    const listing = h("div", { class: "folder-list", "aria-live": "polite" });
    const currentPath = h("div", { class: "folder-current mono", "aria-live": "polite" });
    const up = button("Up", () => { if (current?.parent_path) void load(current.parent_path); }, "secondary", { disabled: true });
    const useFolder = button("Use this folder", () => {
      if (!current) return;
      resolve(current.path);
      instance.close();
    }, "primary", { disabled: true });

    async function load(path?: string, offset = 0, preserveSearch = false): Promise<void> {
      clearTimeout(searchTimer);
      if (!preserveSearch) search.value = "";
      const id = ++requestId;
      listing.replaceChildren(loading("Reading folders"));
      useFolder.disabled = true;
      up.disabled = true;
      try {
        const params = new URLSearchParams({ offset: String(offset), search: search.value });
        if (path) params.set("path", path);
        const result = await api<RepositoryFolders>(`/api/repository-folders?${params}`);
        if (closed || id !== requestId) return;
        current = result;
        address.value = result.path;
        currentPath.textContent = result.path;
        locations.replaceChildren(...result.roots.map((root) => h("option", { value: root.path }, `${root.name} (${root.path})`)));
        const containingRoot = [...result.roots].sort((left, right) => right.path.length - left.path.length)
          .find((root) => result.path === root.path || result.path.startsWith(`${root.path}/`));
        locations.value = containingRoot?.path ?? result.roots[0]?.path ?? "";
        up.disabled = result.parent_path === null;
        useFolder.disabled = false;
        listing.replaceChildren(...result.folders.map((folder) =>
          button(folder.name, () => void load(folder.path), "ghost", {
            class: "folder-row", "aria-label": `Open folder ${folder.name}`,
            dataset: { repository: String(folder.is_repository) },
          }),
        ));
        for (const [index, folder] of result.folders.entries()) {
          if (folder.is_repository) listing.children[index]?.append(h("span", { class: "folder-kind" }, "Git repository"));
        }
        if (result.folders.length === 0) {
          listing.append(emptyState(search.value ? "No matching folders" : "No subfolders", "You can select the current folder."));
        }
        if (offset > 0 || result.next_offset !== null) {
          listing.append(h("div", { class: "row folder-pagination" },
            button("Previous", () => void load(result.path, Math.max(0, offset - 100), true), "secondary", { disabled: offset === 0 }),
            button("Next", () => { if (result.next_offset !== null) void load(result.path, result.next_offset, true); }, "secondary", { disabled: result.next_offset === null }),
          ));
        }
      } catch (error) {
        if (closed || id !== requestId) return;
        listing.replaceChildren(errorState(error instanceof Error ? error.message : "Unable to read folders", () => void load(path, offset, true)));
        if (current) listing.append(button("Back to previous folder", () => void load(current!.path), "secondary"));
      }
    }

    locations.addEventListener("change", () => void load(locations.value));
    search.addEventListener("input", () => {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(() => void load(current?.path, 0, true), 180);
    });
    const pathForm = h("form", {
      class: "folder-address",
      onsubmit: (event: Event) => { event.preventDefault(); void load(address.value.trim()); },
    }, field("Folder path", address), h("button", { class: "btn btn-secondary", type: "submit" }, "Open"));
    const content = h("div", { class: "form" },
      h("p", { class: "modal-copy" }, "Choose a repository or any subfolder on this host."),
      field("Location", locations),
      h("div", { class: "folder-toolbar" }, up, currentPath),
      field("Find a folder", search),
      listing,
      h("details", { class: "form-advanced" }, h("summary", { tabindex: "0" }, "Go to a path"), pathForm),
    );
    const instance = modal("Choose repository folder", content,
      h("div", { class: "row" }, button("Cancel", () => instance.close(), "secondary"), useFolder),
      { onClose: () => { closed = true; clearTimeout(searchTimer); resolve(null); }, initialFocus: locations },
    );
    void load(initialPath);
  });
}
