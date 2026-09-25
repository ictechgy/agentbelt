// SBPL that keeps a sandboxed child from planting git state the host later obeys.
// Host git trusts every gitdir it discovers: a config in a new nested repository
// registered as a gitlink, a `.git` symlink or `gitdir:` file pointing at a
// child-written directory, `commondir`, or `modules/*/config` all make an
// unsandboxed `git status` run a child-chosen core.fsmonitor (measured with git
// 2.54 on 2026-09-24). So no `.git` entry may be created, replaced or removed
// anywhere below the workspace, and every existing gitdir keeps its config,
// hooks and redirections read-only. Objects, refs, index and HEAD stay writable:
// commit, branch, checkout, stash and gc work; clone/init/submodule/worktree
// inside the workspace do not. objects/info/alternates stays writable: it redirects
// object reads only, never execution, and the child already controls workspace content.
// Kept free of runtime imports so tests can load it without the SRT package.

const LOCKED = ['config', 'config\\.worktree', 'hooks', 'info/attributes', 'commondir', 'modules', 'worktrees'];

// Seatbelt on macOS 26 already matched `.GIT` and `COMMONDIR` against lowercase rules
// (measured 2026-09-24); spelled out anyway so the lock does not rest on that.
const anyCase = text => text.replace(/[a-z]/g, c => '[' + c + c.toUpperCase() + ']');

export function gitLockRules(root) {
  if (typeof root !== 'string' || !root.startsWith('/') || root.includes('\n') || root.includes('"')) {
    throw new Error('invalid git lock root');
  }
  const base = '^' + root.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '/(.*/)?' + anyCase('\\.git');
  const locked = LOCKED.map(anyCase).join('|');
  const inside = JSON.stringify(base + '/(' + locked + ')(/|$)');
  // SRT re-allows file-write-create/unlink for every write root as concrete operations, and a
  // concrete allow beats a wildcard deny: `file-write*` alone let new files such as
  // commondir through (measured in a real run_confined). Deny the concrete operations too.
  return '\n(deny file-write-create file-write-unlink (regex ' + JSON.stringify(base + '$') + '))\n' +
    '(deny file-write* (regex ' + inside + '))\n' +
    '(deny file-write-create file-write-unlink (regex ' + inside + '))\n';
}

// Package managers that fetch git dependencies create repositories of their own: SwiftPM
// (<workspace>/.build/checkouts), dart pub (<home>/.pub-cache/git) and cargo (<home>/.cargo/git).
// Inside these trees only the git lock itself is undone (the same two patterns), so every other
// write denial there (secret names, SRT's own) still applies. agentbelt audits the workspace after
// the session for repositories that left them (git_audit.py).
export function gitToolRules(paths) {
  if (!Array.isArray(paths) || paths.some(p => typeof p !== 'string' || !p.startsWith('/') || p.includes('\n')
      || p.includes('"') || p.split('/').includes('..'))) {
    throw new Error('invalid git tool cache');
  }
  return paths.map(cache => {
    const base = '^' + cache.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '/(.*/)?' + anyCase('\\.git');
    const inside = JSON.stringify(base + '/(' + LOCKED.map(anyCase).join('|') + ')(/|$)');
    return '\n(allow file-write-create file-write-unlink (regex ' + JSON.stringify(base + '$') + '))\n' +
      '(allow file-write* file-write-create file-write-unlink (regex ' + inside + '))\n';
  }).join('');
}

// Seatbelt matches resolved paths. A write root created on demand (TemporaryItems) may not exist
// at launch, so resolve its nearest existing ancestor and keep the rest as spelled.
export function resolveRoot(root, fs) {
  const missing = [];
  let current = root;
  while (!fs.existsSync(current)) {
    const parent = current.slice(0, current.lastIndexOf('/')) || '/';
    if (parent === current) break;
    missing.unshift(current.slice(current.lastIndexOf('/') + 1));
    current = parent;
  }
  const resolved = fs.realpathSync(current);
  return missing.length ? (resolved === '/' ? '' : resolved) + '/' + missing.join('/') : resolved;
}
