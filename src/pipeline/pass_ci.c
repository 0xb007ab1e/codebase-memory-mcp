/*
 * pass_ci.c — the command lines CI configurations run, handed to the shell
 * layer (pass_shell.c), which links what they deploy and start.
 *
 * PHASE 3 P3.5. Read with tree-sitter-yaml:
 *  - GitHub Actions: a workflow (.github/workflows/<name>.yml|yaml at the
 *    root -- GitHub reads no other) and a composite action (any
 *    action.yml|yaml with runs.using: composite). A step's run: is a shell
 *    text unless a shell other than bash / sh is named (step > job
 *    defaults.run > workflow defaults.run), or none is and the job's runs-on
 *    names a Windows runner (whose default is pwsh). It starts in the
 *    workspace -- the root -- or the working-directory (same precedence); env
 *    literals (workflow < job < step) are variables, a value holding `${{` an
 *    unknown one. In the text, `${{ github.workspace }}` is
 *    $GITHUB_WORKSPACE, `${{ github.action_path }}` $GITHUB_ACTION_PATH, any
 *    other `${{ }}` an unknown variable (its line breaks kept).
 *  - Prow: a file with a top-level presubmits / postsubmits / periodics key
 *    (in-repo job config). A job container's command + args is exec'd, no
 *    shell: the words are literal, a kubelet `$(VAR)` unknown; `bash -c TEXT`
 *    runs TEXT as shell. A decorated job starts in the repository's checkout
 *    (the root); undecorated, with an extra_ref taking the working directory,
 *    or with a container workingDir, the directory is unknown.
 * Scalars: plain, quoted and literal block (|) values; a folded (>) block or
 * one with an indentation indicator is skipped.
 */
#include "foundation/constants.h"
#include "foundation/compat.h"
#include "pipeline/pipeline_internal.h"
#include "cbm.h"
#include "lang_specs.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const char CI_GHA[] = "github-actions";
static const char CI_PROW[] = "prow";

static const char CI_EXPR_OPEN[] = "${{";
#define CI_EXPR_OPEN_LEN (sizeof(CI_EXPR_OPEN) - SKIP_ONE)
static const char CI_QUOTED_QUOTE[] = "'\\''";
#define CI_QUOTED_QUOTE_LEN (sizeof(CI_QUOTED_QUOTE) - SKIP_ONE)
/* A rewritten run: text is at most this many times the original: the
 * shortest expression `${{}}` (5 bytes) becomes `${__ci_expr}` (12). */
enum { CI_TEXT_GROWTH = 3 };

typedef struct {
    CBMArena *a;
    const char *src;
    const char *rel;
    cbm_ci_cmd_fn fn;
    void *ud;
} ci_t;

/* name, value pairs; a value NULL: unknown. */
typedef struct {
    const char **kv;
    int n;
} ci_env_t;

/* What a step inherits from its job and workflow. */
typedef struct {
    ci_env_t env;
    const char *wd;    /* working-directory; NULL: none named */
    const char *shell; /* NULL: none named */
    bool windows;
    const char *action_dir; /* a composite action's directory */
} ci_scope_t;

typedef struct {
    const char *key;
    TSNode value; /* may be null: `key:` without a value */
} ci_pair_t;

static bool ci_type(TSNode n, const char *t) {
    return !ts_node_is_null(n) && strcmp(ts_node_type(n), t) == 0;
}

/* The content of a node, through block_node / flow_node wrappers and past
 * comments, anchors and tags; null for nothing (an alias stays an alias). */
static TSNode ci_content(TSNode n) {
    while (ci_type(n, "block_node") || ci_type(n, "flow_node")) {
        TSNode next = {0};
        uint32_t k = ts_node_named_child_count(n);
        for (uint32_t i = 0; i < k; i++) {
            TSNode c = ts_node_named_child(n, i);
            if (!ci_type(c, "comment") && !ci_type(c, "anchor") && !ci_type(c, "tag")) {
                next = c;
                break;
            }
        }
        n = next;
    }
    return n;
}

/* A flow scalar's value: line breaks folded (a single one to a space, n
 * empty lines to n newlines), each line trimmed; `q` the quote (0: plain)
 * whose escapes apply. */
static const char *ci_fold(CBMArena *a, const char *s, size_t n, char q) {
    char *out = cbm_arena_alloc(a, n + SKIP_ONE);
    if (!out) {
        return NULL;
    }
    size_t o = 0;
    size_t i = 0;
    while (i < n) {
        char ch = s[i];
        if (ch == '\n' || ch == '\r') {
            while (o > 0 && (out[o - SKIP_ONE] == ' ' || out[o - SKIP_ONE] == '\t')) {
                o--;
            }
            size_t j = i;
            int breaks = 0;
            while (j < n && (s[j] == ' ' || s[j] == '\t' || s[j] == '\r' || s[j] == '\n')) {
                breaks += s[j] == '\n';
                j++;
            }
            if (breaks > SKIP_ONE) {
                for (int k = SKIP_ONE; k < breaks; k++) {
                    out[o++] = '\n';
                }
            } else {
                out[o++] = ' ';
            }
            i = j;
            continue;
        }
        if (q == '"' && ch == '\\' && i + SKIP_ONE < n) {
            char x = s[i + SKIP_ONE];
            i += PAIR_LEN;
            if (x == '\n' || x == '\r') {
                while (i < n && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n')) {
                    i++;
                }
                continue;
            }
            out[o++] = x == 'n' ? '\n' : x == 't' ? '\t' : x;
            continue;
        }
        if (q == '\'' && ch == '\'' && i + SKIP_ONE < n && s[i + SKIP_ONE] == '\'') {
            out[o++] = '\'';
            i += PAIR_LEN;
            continue;
        }
        out[o++] = ch;
        i++;
    }
    out[o] = '\0';
    return out;
}

/* A literal block scalar's value (s at its `|`); NULL for a folded block or
 * an indentation indicator. */
static const char *ci_literal(CBMArena *a, const char *s, size_t n) {
    if (n == 0 || s[0] != '|') {
        return NULL;
    }
    size_t i = SKIP_ONE;
    while (i < n && s[i] != '\n' && s[i] != '#') {
        if (s[i] >= '1' && s[i] <= '9') {
            return NULL;
        }
        i++;
    }
    while (i < n && s[i] != '\n') {
        i++;
    }
    i += i < n ? SKIP_ONE : 0;
    size_t indent = 0;
    for (size_t j = i; j < n;) {
        size_t k = j;
        while (k < n && s[k] == ' ') {
            k++;
        }
        if (k < n && s[k] != '\n' && s[k] != '\r') {
            indent = k - j;
            break;
        }
        while (k < n && s[k] != '\n') {
            k++;
        }
        j = k + SKIP_ONE;
    }
    char *out = cbm_arena_alloc(a, n + SKIP_ONE);
    if (!out) {
        return NULL;
    }
    size_t o = 0;
    while (i < n) {
        size_t e = i;
        while (e < n && s[e] != '\n') {
            e++;
        }
        size_t k = i;
        while (k < e && k - i < indent && s[k] == ' ') {
            k++;
        }
        if (k - i == indent) {
            memcpy(out + o, s + k, e - k);
            o += e - k;
        }
        if (o > 0 && out[o - SKIP_ONE] == '\r') {
            o--;
        }
        if (e < n) {
            out[o++] = '\n';
        }
        i = e + SKIP_ONE;
    }
    out[o] = '\0';
    return out;
}

/* A scalar's value and the 0-based row of its first character; NULL: no
 * scalar this reader decodes. */
static const char *ci_scalar(const ci_t *c, TSNode n, int *row) {
    n = ci_content(n);
    if (ts_node_is_null(n)) {
        return NULL;
    }
    uint32_t b = ts_node_start_byte(n);
    size_t len = ts_node_end_byte(n) - b;
    const char *s = c->src + b;
    if (row) {
        *row = (int)ts_node_start_point(n).row;
    }
    if (ci_type(n, "plain_scalar")) {
        return ci_fold(c->a, s, len, 0);
    }
    if (len >= PAIR_LEN && ci_type(n, "double_quote_scalar")) {
        return ci_fold(c->a, s + SKIP_ONE, len - PAIR_LEN, '"');
    }
    if (len >= PAIR_LEN && ci_type(n, "single_quote_scalar")) {
        return ci_fold(c->a, s + SKIP_ONE, len - PAIR_LEN, '\'');
    }
    if (ci_type(n, "block_scalar")) {
        if (row) {
            (*row)++;
        }
        return ci_literal(c->a, s, len);
    }
    return NULL;
}

/* The pairs of mapping `m` with a scalar key; *n their count. */
static ci_pair_t *ci_pairs(const ci_t *c, TSNode m, int *n) {
    *n = 0;
    m = ci_content(m);
    if (!ci_type(m, "block_mapping") && !ci_type(m, "flow_mapping")) {
        return NULL;
    }
    uint32_t k = ts_node_named_child_count(m);
    ci_pair_t *out = cbm_arena_alloc(c->a, (k + SKIP_ONE) * sizeof(*out));
    if (!out) {
        return NULL;
    }
    for (uint32_t i = 0; i < k; i++) {
        TSNode p = ts_node_named_child(m, i);
        if (!ci_type(p, "block_mapping_pair") && !ci_type(p, "flow_pair")) {
            continue;
        }
        const char *key = ci_scalar(c, ts_node_child_by_field_name(p, TS_FIELD("key")), NULL);
        if (key) {
            out[(*n)++] = (ci_pair_t){key, ts_node_child_by_field_name(p, TS_FIELD("value"))};
        }
    }
    return out;
}

/* The value of `key` in mapping `m` (the first such pair); null: none. */
static TSNode ci_get(const ci_t *c, TSNode m, const char *key) {
    int n = 0;
    ci_pair_t *pairs = ci_pairs(c, m, &n);
    for (int i = 0; i < n; i++) {
        if (strcmp(pairs[i].key, key) == 0) {
            return pairs[i].value;
        }
    }
    TSNode none = {0};
    return none;
}

static const char *ci_get_str(const ci_t *c, TSNode m, const char *key) {
    return ci_scalar(c, ci_get(c, m, key), NULL);
}

/* The item contents of a sequence; *n their count. */
static TSNode *ci_items(const ci_t *c, TSNode seq, int *n) {
    *n = 0;
    seq = ci_content(seq);
    bool block = ci_type(seq, "block_sequence");
    if (!block && !ci_type(seq, "flow_sequence")) {
        return NULL;
    }
    uint32_t k = ts_node_named_child_count(seq);
    TSNode *out = cbm_arena_alloc(c->a, (k + SKIP_ONE) * sizeof(*out));
    if (!out) {
        return NULL;
    }
    for (uint32_t i = 0; i < k; i++) {
        TSNode it = ts_node_named_child(seq, i);
        if (block && ci_type(it, "block_sequence_item")) {
            TSNode v = {0};
            for (uint32_t j = 0; j < ts_node_named_child_count(it); j++) {
                TSNode x = ts_node_named_child(it, j);
                if (!ci_type(x, "comment")) {
                    v = x;
                    break;
                }
            }
            out[(*n)++] = ci_content(v);
        } else if (!block && ci_type(it, "flow_node")) {
            out[(*n)++] = ci_content(it);
        }
    }
    return out;
}

/* `base` and then the pairs of env mapping `m`: a non-scalar or `${{` value
 * is unknown, an absent one empty. */
static ci_env_t ci_env_add(const ci_t *c, const ci_env_t *base, TSNode m) {
    int n = 0;
    ci_pair_t *pairs = ci_pairs(c, m, &n);
    int bn = base ? base->n : 0;
    ci_env_t out = {cbm_arena_alloc(c->a, (size_t)(bn + n + SKIP_ONE) * PAIR_LEN * sizeof(char *)),
                    0};
    if (!out.kv) {
        return base ? *base : out;
    }
    for (int i = 0; i < bn; i++) {
        out.kv[PAIR_LEN * out.n] = base->kv[PAIR_LEN * i];
        out.kv[PAIR_LEN * out.n + SKIP_ONE] = base->kv[PAIR_LEN * i + SKIP_ONE];
        out.n++;
    }
    for (int i = 0; i < n; i++) {
        const char *v = ts_node_is_null(pairs[i].value) ? "" : ci_scalar(c, pairs[i].value, NULL);
        out.kv[PAIR_LEN * out.n] = pairs[i].key;
        out.kv[PAIR_LEN * out.n + SKIP_ONE] = v && !strstr(v, "${{") ? v : NULL;
        out.n++;
    }
    return out;
}

/* ── GitHub Actions ────────────────────────────────────────────────── */

/* The n bytes at b are exactly `word`. */
static bool ci_span_is(const char *b, size_t n, const char *word) {
    return strlen(word) == n && strncmp(b, word, n) == 0;
}

/* The run: text with its `${{ }}` expressions replaced (see the header),
 * CBM_SZ_16 zero bytes past its end. */
static const char *ci_gha_text(CBMArena *a, const char *t, size_t *len) {
    size_t n = strlen(t);
    char *out = cbm_arena_alloc(a, n * CI_TEXT_GROWTH + CBM_SZ_16 + CBM_SZ_16);
    if (!out) {
        return NULL;
    }
    size_t o = 0;
    size_t i = 0;
    while (i < n) {
        const char *open = t + i + CI_EXPR_OPEN_LEN;
        const char *end =
            strncmp(t + i, CI_EXPR_OPEN, CI_EXPR_OPEN_LEN) == 0 ? strstr(open, "}}") : NULL;
        if (!end) {
            out[o++] = t[i++];
            continue;
        }
        const char *b = open;
        const char *e = end;
        while (b < e && (*b == ' ' || *b == '\t')) {
            b++;
        }
        while (e > b && (e[-SKIP_ONE] == ' ' || e[-SKIP_ONE] == '\t')) {
            e--;
        }
        size_t il = (size_t)(e - b);
        const char *rep = "${__ci_expr}";
        if (ci_span_is(b, il, "github.workspace")) {
            rep = "${GITHUB_WORKSPACE}";
        } else if (ci_span_is(b, il, "github.action_path")) {
            rep = "${GITHUB_ACTION_PATH}";
        }
        size_t rl = strlen(rep);
        memcpy(out + o, rep, rl);
        o += rl;
        for (const char *p = open; p < end; p++) {
            if (*p == '\n') {
                out[o++] = '\n';
            }
        }
        i = (size_t)(end - t) + PAIR_LEN;
    }
    memset(out + o, 0, CBM_SZ_16);
    *len = o;
    return out;
}

/* A shell GitHub runs a step with as bash: `bash ...` / `sh ...`. */
static bool ci_bash_shell(const char *sh) {
    size_t k = strncmp(sh, "bash", strlen("bash")) == 0 ? strlen("bash")
               : strncmp(sh, "sh", strlen("sh")) == 0   ? strlen("sh")
                                                        : 0;
    if (!k) {
        return false;
    }
    char ch = sh[k];
    return !(ch == '_' || (ch >= '0' && ch <= '9') || ((ch | ' ') >= 'a' && (ch | ' ') <= 'z'));
}

/* `s` contains `word` (lowercase ASCII), ignoring case. */
static bool ci_has_word(const char *s, const char *word) {
    size_t wl = strlen(word);
    for (const char *p = s; p && *p; p++) {
        size_t k = 0;
        while (k < wl && p[k] && (char)(p[k] | ' ') == word[k]) {
            k++;
        }
        if (k == wl) {
            return true;
        }
    }
    return false;
}

/* runs-on names a Windows runner: a label, or any label of a list. */
static bool ci_windows(const ci_t *c, TSNode runs_on) {
    int n = 0;
    TSNode *items = ci_items(c, runs_on, &n);
    if (!items) {
        return ci_has_word(ci_scalar(c, runs_on, NULL), "windows");
    }
    for (int i = 0; i < n; i++) {
        if (ci_has_word(ci_scalar(c, items[i], NULL), "windows")) {
            return true;
        }
    }
    return false;
}

static const char *ci_run_default(const ci_t *c, TSNode m, const char *key) {
    return ci_get_str(c, ci_get(c, ci_get(c, m, "defaults"), "run"), key);
}

static void ci_gha_steps(const ci_t *c, TSNode steps, const char *job, const ci_scope_t *sc) {
    int n = 0;
    TSNode *items = ci_items(c, steps, &n);
    for (int i = 0; i < n; i++) {
        int row = 0;
        const char *run = ci_scalar(c, ci_get(c, items[i], "run"), &row);
        if (!run) {
            continue;
        }
        const char *shell = ci_get_str(c, items[i], "shell");
        shell = shell ? shell : sc->shell;
        if (shell && shell[0] ? !ci_bash_shell(shell) : sc->windows) {
            continue;
        }
        const char *wd = ci_get_str(c, items[i], "working-directory");
        wd = wd ? wd : sc->wd;
        if (!wd) {
            wd = "";
        } else if (strstr(wd, "${{") || wd[0] == '/' || wd[0] == '~') {
            wd = NULL;
        }
        ci_env_t env = ci_env_add(c, &sc->env, ci_get(c, items[i], "env"));
        size_t len = 0;
        const char *text = ci_gha_text(c->a, run, &len);
        if (!text) {
            continue;
        }
        cbm_ci_cmd_t cmd = {.ci = CI_GHA,
                            .job = job,
                            .text = text,
                            .len = len,
                            .row = row,
                            .wd = wd,
                            .action_dir = sc->action_dir,
                            .env = env.kv,
                            .nenv = env.n,
                            .exec = false};
        c->fn(&cmd, c->ud);
    }
}

static void ci_workflow(const ci_t *c, TSNode root) {
    ci_env_t wenv = ci_env_add(c, NULL, ci_get(c, root, "env"));
    const char *wwd = ci_run_default(c, root, "working-directory");
    const char *wsh = ci_run_default(c, root, "shell");
    int n = 0;
    ci_pair_t *jobs = ci_pairs(c, ci_get(c, root, "jobs"), &n);
    for (int i = 0; i < n; i++) {
        TSNode j = jobs[i].value;
        const char *wd = ci_run_default(c, j, "working-directory");
        const char *sh = ci_run_default(c, j, "shell");
        ci_scope_t sc = {.env = ci_env_add(c, &wenv, ci_get(c, j, "env")),
                         .wd = wd ? wd : wwd,
                         .shell = sh ? sh : wsh,
                         .windows = ci_windows(c, ci_get(c, j, "runs-on")),
                         .action_dir = NULL};
        ci_gha_steps(c, ci_get(c, j, "steps"), jobs[i].key, &sc);
    }
}

static void ci_action(const ci_t *c, TSNode root) {
    TSNode runs = ci_get(c, root, "runs");
    const char *using = ci_get_str(c, runs, "using");
    if (!using || strcmp(using, "composite") != 0) {
        return;
    }
    const char *slash = strrchr(c->rel, '/');
    ci_scope_t sc = {.action_dir =
                         slash ? cbm_arena_strndup(c->a, c->rel, (size_t)(slash - c->rel)) : ""};
    ci_gha_steps(c, ci_get(c, runs, "steps"), NULL, &sc);
}

/* ── Prow ──────────────────────────────────────────────────────────── */

static bool ci_is_shell(const char *w) {
    static const char *const shells[] = {"bash", "sh", "zsh", "ksh", "dash", NULL};
    const char *slash = strrchr(w, '/');
    const char *base = slash ? slash + SKIP_ONE : w;
    for (int i = 0; shells[i]; i++) {
        if (strcmp(base, shells[i]) == 0) {
            return true;
        }
    }
    return false;
}

/* argv as one shell line of quoted words (a `$(VAR)` word unknown), with
 * CBM_SZ_16 zero bytes past its end. */
static const char *ci_exec_line(CBMArena *a, const char **w, int n, size_t *len) {
    size_t cap = CBM_SZ_16 + CBM_SZ_16;
    for (int i = 0; i < n; i++) {
        cap += strlen(w[i]) * CI_QUOTED_QUOTE_LEN + CBM_SZ_16;
    }
    char *out = cbm_arena_alloc(a, cap);
    if (!out) {
        return NULL;
    }
    size_t o = 0;
    for (int i = 0; i < n; i++) {
        if (i) {
            out[o++] = ' ';
        }
        if (strstr(w[i], "$(")) {
            static const char unknown[] = "\"$__k8s_var\"";
            memcpy(out + o, unknown, sizeof(unknown) - SKIP_ONE);
            o += sizeof(unknown) - SKIP_ONE;
            continue;
        }
        out[o++] = '\'';
        for (const char *p = w[i]; *p; p++) {
            if (*p == '\'') {
                memcpy(out + o, CI_QUOTED_QUOTE, CI_QUOTED_QUOTE_LEN);
                o += CI_QUOTED_QUOTE_LEN;
            } else {
                out[o++] = *p;
            }
        }
        out[o++] = '\'';
    }
    memset(out + o, 0, CBM_SZ_16);
    *len = o;
    return out;
}

static void ci_prow_container(const ci_t *c, TSNode ct, const char *job, bool root_wd) {
    int nc = 0;
    int na = 0;
    TSNode *cmd = ci_items(c, ci_get(c, ct, "command"), &nc);
    TSNode *args = ci_items(c, ci_get(c, ct, "args"), &na);
    int n = nc + na;
    if (n == 0) {
        return;
    }
    const char **w = cbm_arena_alloc(c->a, (size_t)n * sizeof(*w));
    int *rows = cbm_arena_alloc(c->a, (size_t)n * sizeof(*rows));
    if (!w || !rows) {
        return;
    }
    for (int i = 0; i < n; i++) {
        w[i] = ci_scalar(c, i < nc ? cmd[i] : args[i - nc], &rows[i]);
        if (!w[i]) {
            return;
        }
    }
    const char *wdir = ci_get_str(c, ct, "workingDir");
    cbm_ci_cmd_t out = {.ci = CI_PROW, .job = job, .wd = root_wd && !(wdir && wdir[0]) ? "" : NULL};
    if (ci_is_shell(w[0])) {
        int k = SKIP_ONE;
        while (k < n && strcmp(w[k], "-c") != 0) {
            k++;
        }
        if (k < n) {
            if (k + SKIP_ONE >= n) {
                return;
            }
            size_t tl = strlen(w[k + SKIP_ONE]);
            char *text = cbm_arena_alloc(c->a, tl + CBM_SZ_16);
            if (!text) {
                return;
            }
            memcpy(text, w[k + SKIP_ONE], tl);
            memset(text + tl, 0, CBM_SZ_16);
            out.text = text;
            out.len = tl;
            out.row = rows[k + SKIP_ONE];
            c->fn(&out, c->ud);
            return;
        }
    }
    out.text = ci_exec_line(c->a, w, n, &out.len);
    out.row = rows[0];
    out.exec = true;
    if (out.text) {
        c->fn(&out, c->ud);
    }
}

static void ci_prow_job(const ci_t *c, TSNode j) {
    const char *name = ci_get_str(c, j, "name");
    const char *decorate = ci_get_str(c, j, "decorate");
    bool root_wd = decorate && strcmp(decorate, "true") == 0;
    int n = 0;
    TSNode *refs = ci_items(c, ci_get(c, j, "extra_refs"), &n);
    for (int i = 0; i < n; i++) {
        const char *wd = ci_get_str(c, refs[i], "workdir");
        root_wd = root_wd && !(wd && strcmp(wd, "true") == 0);
    }
    TSNode *cts = ci_items(c, ci_get(c, ci_get(c, j, "spec"), "containers"), &n);
    for (int i = 0; i < n; i++) {
        ci_prow_container(c, cts[i], name, root_wd);
    }
}

static void ci_prow_jobs(const ci_t *c, TSNode seq) {
    int n = 0;
    TSNode *jobs = ci_items(c, seq, &n);
    for (int i = 0; i < n; i++) {
        ci_prow_job(c, jobs[i]);
    }
}

static void ci_prow(const ci_t *c, TSNode root) {
    static const char *const keys[] = {"presubmits", "postsubmits", "periodics", NULL};
    for (int k = 0; keys[k]; k++) {
        TSNode v = ci_content(ci_get(c, root, keys[k]));
        int n = 0;
        ci_pair_t *repos = ci_pairs(c, v, &n);
        if (!repos) {
            ci_prow_jobs(c, v);
            continue;
        }
        for (int i = 0; i < n; i++) {
            ci_prow_jobs(c, repos[i].value);
        }
    }
}

/* ── Entry ─────────────────────────────────────────────────────────── */

static bool ci_yaml_ext(const char *p) {
    const char *dot = strrchr(p, '.');
    return dot && (strcmp(dot, ".yml") == 0 || strcmp(dot, ".yaml") == 0);
}

static bool ci_workflow_path(const char *rel) {
    static const char dir[] = ".github/workflows/";
    return strncmp(rel, dir, sizeof(dir) - SKIP_ONE) == 0 &&
           !strchr(rel + sizeof(dir) - SKIP_ONE, '/') && ci_yaml_ext(rel);
}

static bool ci_action_path(const char *rel) {
    const char *slash = strrchr(rel, '/');
    const char *base = slash ? slash + SKIP_ONE : rel;
    return strcmp(base, "action.yml") == 0 || strcmp(base, "action.yaml") == 0;
}

bool cbm_ci_path(const char *rel) {
    return rel && (ci_workflow_path(rel) || ci_action_path(rel));
}

void cbm_ci_commands(CBMArena *a, const char *rel, const char *src, size_t len, cbm_ci_cmd_fn fn,
                     void *ud) {
    if (!ci_yaml_ext(rel)) {
        return;
    }
    TSParser *parser = ts_parser_new();
    if (!parser) {
        return;
    }
    TSTree *tree = NULL;
    if (ts_parser_set_language(parser, cbm_ts_language(CBM_LANG_YAML))) {
        tree = ts_parser_parse_string(parser, NULL, src, (uint32_t)len);
    }
    if (tree) {
        ci_t c = {.a = a, .src = src, .rel = rel, .fn = fn, .ud = ud};
        TSNode stream = ts_tree_root_node(tree);
        for (uint32_t i = 0; i < ts_node_named_child_count(stream); i++) {
            TSNode doc = ts_node_named_child(stream, i);
            if (!ci_type(doc, "document")) {
                continue;
            }
            TSNode root = {0};
            for (uint32_t k = 0; k < ts_node_named_child_count(doc); k++) {
                TSNode x = ts_node_named_child(doc, k);
                if (ci_type(x, "block_node") || ci_type(x, "flow_node")) {
                    root = ci_content(x);
                    break;
                }
            }
            if (ci_workflow_path(rel)) {
                ci_workflow(&c, root);
            } else if (ci_action_path(rel)) {
                ci_action(&c, root);
            } else {
                ci_prow(&c, root);
            }
        }
        ts_tree_delete(tree);
    }
    ts_parser_delete(parser);
}
