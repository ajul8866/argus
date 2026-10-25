import { DEFAULT_EXCLUDES } from "../src/repo/inventory.ts";
import { createScopeMatcher, globToRegExp, normalizePath } from "../src/util.ts";

const scope = { include: ["**/*.ts", "**/*.js", "**/*.json"], exclude: DEFAULT_EXCLUDES };
const paths = Array.from({ length: 6_000 }, (_, index) => `src/module-${index % 100}/file-${index}.ts`);

// Retain the original matching path as the benchmark's comparison baseline.
function originalMatches(relativePath: string): boolean {
  const path = normalizePath(relativePath);
  return scope.include.some((glob) => globToRegExp(glob).test(path)) &&
    !scope.exclude.some((glob) => globToRegExp(glob).test(path));
}

const originalTimes: number[] = [];
const reusedTimes: number[] = [];
for (let sample = 0; sample <= 5; sample += 1) {
  const measure = (reuse: boolean) => {
    const start = performance.now();
    const matches = reuse ? createScopeMatcher(scope).matches : originalMatches;
    const count = paths.filter(matches).length;
    const elapsed = performance.now() - start;
    if (count !== paths.length) throw new Error(`Unexpected match count: ${count}`);
    if (sample > 0) (reuse ? reusedTimes : originalTimes).push(elapsed);
  };
  if (sample % 2 === 0) {
    measure(false);
    measure(true);
  } else {
    measure(true);
    measure(false);
  }
}

function median(values: number[]): number {
  return [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)]!;
}

const originalMs = median(originalTimes);
const reusedMs = median(reusedTimes);
console.log(JSON.stringify({
  paths: paths.length,
  patterns: scope.include.length + scope.exclude.length,
  samples: originalTimes.length,
  original_median_ms: Number(originalMs.toFixed(2)),
  reused_median_ms: Number(reusedMs.toFixed(2)),
  speedup: Number((originalMs / reusedMs).toFixed(2)),
}, null, 2));
