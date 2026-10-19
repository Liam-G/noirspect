//! Load a Nargo workspace through the compiler's own crates and produce the
//! optimized SSA of every function the analysis should start from.
//!
//! Loading happens in two steps. *Planning* checks each package and decides
//! the entry points; it is cheap and deterministic. *Lowering* runs the
//! compiler's SSA pipeline for each entry, which can take minutes on large
//! circuits. With a [`Worker`], lowering runs in child processes so a single
//! slow entry can be abandoned after a time budget instead of stalling the run.

use fm::FileManager;
use nargo::package::Package;
use nargo::workspace::Workspace;
use nargo::{insert_all_files_for_workspace_into_file_manager, parse_all, prepare_package};
use nargo_toml::{PackageSelection, get_package_manifest, resolve_workspace_from_toml};
use noirc_driver::{CompileOptions, NOIR_ARTIFACT_VERSION_STRING, check_crate};
use noirc_errors::CustomDiagnostic;
use noirc_evaluator::ssa::ir::function::Function as SsaFunction;
use noirc_evaluator::ssa::ir::map::Id;
use noirc_evaluator::ssa::ssa_gen::generate_ssa;
use noirc_evaluator::ssa::{SsaBuilder, SsaEvaluatorOptions, SsaLogging, primary_passes};
use noirc_frontend::Type;
use noirc_frontend::graph::CrateId;
use noirc_frontend::hir::printer::{crate_to_module, items};
use noirc_frontend::hir::{CheckedContext, Context, ParsedFiles};
use noirc_frontend::monomorphization::monomorphize;
use noirc_frontend::node_interner::FuncId;
use noirc_frontend::token::FunctionAttributeKind;
use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

type FunctionId = Id<SsaFunction>;

/// Which functions become analysis entry points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryMode {
    /// `main` for binaries; every function and generic instantiation for libraries.
    Auto,
    /// Only `main` (binary packages).
    Main,
    /// `main` plus every function and generic instantiation, in every package.
    All,
}

impl EntryMode {
    pub fn as_arg(self) -> &'static str {
        match self {
            EntryMode::Auto => "auto",
            EntryMode::Main => "main",
            EntryMode::All => "all",
        }
    }
}

pub struct EntrySsa {
    pub name: String,
    pub is_main: bool,
    pub ssa: Result<String, String>,
}

pub struct PackageSsa {
    pub name: String,
    pub root: PathBuf,
    pub entries: Vec<EntrySsa>,
    /// Source files of this package (not dependencies).
    pub sources: Vec<SourceFile>,
}

pub struct SourceFile {
    /// The name the compiler prints in SSA locations.
    pub name: String,
    /// The path relative to the workspace root, used in reports.
    pub display: String,
    pub text: String,
}

pub struct WorkspaceSsa {
    pub root: PathBuf,
    pub packages: Vec<PackageSsa>,
}

/// Lower entries in child processes running `exe __lower …`, with a time budget per entry.
#[derive(Debug, Clone)]
pub struct Worker {
    pub exe: PathBuf,
    pub timeout: Duration,
    /// Worker processes to run at once.
    pub jobs: usize,
}

pub struct LoadOptions<'a> {
    pub program_dir: &'a Path,
    pub package: Option<&'a str>,
    pub workspace: bool,
    pub entry: EntryMode,
    pub function_filter: Option<&'a str>,
    pub worker: Option<Worker>,
}

/// The compiler recurses deeply; give it a large stack whatever thread calls us.
const COMPILER_STACK_BYTES: usize = 256 * 1024 * 1024;

/// Run `f` on a thread with a compiler-sized stack and compiler panics silenced.
/// Panics on functions the compiler cannot lower are expected and reported as
/// skipped entries, so their messages stay off stderr.
fn on_compiler_thread<T: Send>(f: impl FnOnce() -> Result<T, String> + Send) -> Result<T, String> {
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::thread::scope(|scope| {
        std::thread::Builder::new()
            .stack_size(COMPILER_STACK_BYTES)
            .spawn_scoped(scope, f)
            .map_err(|e| format!("cannot start compiler thread: {e}"))?
            .join()
            .map_err(|_| "compiler thread panicked".to_string())?
    });
    std::panic::set_hook(previous_hook);
    result
}

pub fn load(options: &LoadOptions) -> Result<WorkspaceSsa, String> {
    on_compiler_thread(|| load_on_current_thread(options))
}

struct Loaded {
    workspace: Workspace,
    file_manager: Arc<FileManager>,
    parsed_files: Arc<ParsedFiles>,
}

fn load_workspace(program_dir: &Path, package: Option<&str>, all: bool) -> Result<Loaded, String> {
    let program_dir = program_dir
        .canonicalize()
        .map_err(|e| format!("cannot open {}: {e}", program_dir.display()))?;
    let toml_path = get_package_manifest(&program_dir).map_err(|e| e.to_string())?;
    let selection = match package {
        Some(name) => PackageSelection::Selected(
            name.parse()
                .map_err(|_| format!("invalid package name `{name}`"))?,
        ),
        None if all => PackageSelection::All,
        None => PackageSelection::DefaultOrAll,
    };
    let workspace = resolve_workspace_from_toml(
        &toml_path,
        selection,
        Some(NOIR_ARTIFACT_VERSION_STRING.to_string()),
    )
    .map_err(|e| e.to_string())?;
    let mut file_manager = workspace.new_file_manager();
    insert_all_files_for_workspace_into_file_manager(&workspace, &mut file_manager);
    let parsed_files = parse_all(&file_manager);
    Ok(Loaded {
        workspace,
        file_manager: Arc::new(file_manager),
        parsed_files: Arc::new(parsed_files),
    })
}

fn load_on_current_thread(options: &LoadOptions) -> Result<WorkspaceSsa, String> {
    let loaded = load_workspace(options.program_dir, options.package, options.workspace)?;
    let mut packages = Vec::new();
    for package in &loaded.workspace {
        let planning = std::time::Instant::now();
        let mut prepared = PreparedPackage::new(&loaded, package)?;
        let plan = prepared.plan(options.entry, options.function_filter);
        // A worker checks and plans the package again before its first entry,
        // which on large crates takes longer than one entry's budget.
        let startup = planning.elapsed() * 3 + Duration::from_secs(30);
        let entries = match &options.worker {
            None => plan
                .iter()
                .map(|entry| prepared.lower_entry(entry))
                .collect(),
            Some(worker) => lower_in_workers(worker, options, package, &plan, startup),
        };
        packages.push(PackageSsa {
            name: package.name.to_string(),
            root: package.root_dir.clone(),
            entries,
            sources: prepared.sources(),
        });
    }
    Ok(WorkspaceSsa {
        root: loaded.workspace.root_dir.clone(),
        packages,
    })
}

#[derive(Debug, Clone)]
pub struct PlannedEntry {
    pub name: String,
    pub is_main: bool,
    func: FuncId,
    /// Analyze this SSA function of `func`'s program as the entry point instead of `func`.
    instance: Option<FunctionId>,
}

struct PreparedPackage<'a> {
    loaded: &'a Loaded,
    package: &'a Package,
    context: CheckedContext,
    crate_id: CrateId,
    ssa_options: SsaEvaluatorOptions,
}

impl<'a> PreparedPackage<'a> {
    fn new(loaded: &'a Loaded, package: &'a Package) -> Result<Self, String> {
        let (context, crate_id) =
            prepare_package(&loaded.file_manager, &loaded.parsed_files, package);
        let compile_options = CompileOptions {
            silence_warnings: true,
            ..CompileOptions::default()
        };
        let (context, checked) = check_crate(context, crate_id, &compile_options);
        if let Err(errors) = checked {
            let errors: Vec<_> = errors.iter().filter(|d| d.is_error()).collect();
            return Err(format!(
                "package `{}` does not compile:\n{}",
                package.name,
                render_diagnostics(&errors, &loaded.file_manager)
            ));
        }
        let ssa_options =
            compile_options.as_ssa_options(loaded.workspace.package_build_path(package));
        Ok(PreparedPackage {
            loaded,
            package,
            context,
            crate_id,
            ssa_options,
        })
    }

    fn plan(&mut self, mode: EntryMode, filter: Option<&str>) -> Vec<PlannedEntry> {
        let matches_filter =
            |name: &str| filter.is_none_or(|f| name == f || name.ends_with(&format!("::{f}")));
        let entry = |name: String, is_main: bool, func: FuncId, instance: Option<FunctionId>| {
            PlannedEntry {
                name,
                is_main,
                func,
                instance,
            }
        };
        let main = self.context.get_main_function(&self.crate_id);
        let mut plan = Vec::new();
        if let Some(main) = main {
            plan.push(entry("main".to_string(), true, main, None));
        }
        let main_only =
            mode == EntryMode::Main || (mode == EntryMode::Auto && self.package.is_binary());
        if main_only {
            plan.retain(|e| matches_filter(&e.name));
            return plan;
        }

        let functions = crate_functions(&self.context, self.crate_id);
        for func in &functions.concrete {
            if Some(*func) != main {
                let name = self
                    .context
                    .fully_qualified_function_name(&self.crate_id, func);
                plan.push(entry(name, false, *func, None));
            }
        }
        plan.retain(|e| matches_filter(&e.name));

        // Generic functions cannot be lowered on their own. Their concrete
        // instantiations exist in the SSA of every function that calls them
        // (tests included), so each one is analyzed as its own entry point.
        if !functions.generic_names.is_empty() {
            let sources: Vec<FuncId> = functions
                .concrete
                .iter()
                .chain(&functions.tests)
                .copied()
                .chain(main)
                .collect();
            let mut covered = BTreeSet::new();
            for source in sources {
                for (instance, name) in
                    generic_instances(&self.context, source, &functions.generic_names)
                {
                    if !matches_filter(&name) || !covered.insert(name.clone()) {
                        continue;
                    }
                    let label = format!(
                        "{name} (instantiated from {})",
                        self.context.function_name(&source)
                    );
                    plan.push(entry(label, false, source, Some(instance)));
                }
            }
        }
        plan
    }

    fn lower_entry(&mut self, entry: &PlannedEntry) -> EntrySsa {
        let ssa = optimized_ssa(&self.context, entry.func, entry.instance, &self.ssa_options);
        EntrySsa {
            name: entry.name.clone(),
            is_main: entry.is_main,
            ssa,
        }
    }

    fn sources(&self) -> Vec<SourceFile> {
        let file_manager = &self.loaded.file_manager;
        let mut sources: Vec<SourceFile> = self
            .context
            .crate_files(&self.crate_id)
            .iter()
            .filter_map(|file_id| {
                let path = file_manager.path(*file_id)?;
                Some(SourceFile {
                    name: file_manager
                        .as_file_map()
                        .get_name(*file_id)
                        .ok()?
                        .to_string(),
                    display: display_name(&self.loaded.workspace.root_dir, path),
                    text: file_manager.fetch_file(*file_id)?.to_string(),
                })
            })
            .collect();
        sources.sort_by(|a, b| a.display.cmp(&b.display));
        sources
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct WorkerLine {
    index: usize,
    ssa: Option<String>,
    error: Option<String>,
}

/// First line a worker prints, so the parent can check both planned alike.
#[derive(serde::Serialize, serde::Deserialize)]
struct WorkerPlan {
    plan: Vec<String>,
}

/// Entry point of the hidden `__lower` subcommand: plan `package` exactly as
/// the parent did, print the plan, then lower each entry index read from stdin
/// and answer with one JSON line, until stdin closes.
pub fn worker_main(
    program_dir: &Path,
    package: &str,
    entry: EntryMode,
    function_filter: Option<&str>,
) -> Result<(), String> {
    on_compiler_thread(|| {
        let loaded = load_workspace(program_dir, Some(package), false)?;
        let package = loaded
            .workspace
            .into_iter()
            .next()
            .ok_or("package not found")?;
        let mut prepared = PreparedPackage::new(&loaded, package)?;
        let plan = prepared.plan(entry, function_filter);
        let mut stdout = std::io::stdout().lock();
        let mut send = |line: String| {
            writeln!(stdout, "{line}")
                .and_then(|_| stdout.flush())
                .map_err(|e| e.to_string())
        };
        let header = WorkerPlan {
            plan: plan.iter().map(|e| e.name.clone()).collect(),
        };
        send(serde_json::to_string(&header).map_err(|e| e.to_string())?)?;
        for line in std::io::stdin().lock().lines() {
            let line = line.map_err(|e| e.to_string())?;
            let Some(planned) = line
                .trim()
                .parse::<usize>()
                .ok()
                .and_then(|i| plan.get(i).map(|p| (i, p)))
            else {
                continue;
            };
            let (index, planned) = planned;
            let (ssa, error) = match prepared.lower_entry(planned).ssa {
                Ok(ssa) => (Some(ssa), None),
                Err(e) => (None, Some(e)),
            };
            send(
                serde_json::to_string(&WorkerLine { index, ssa, error })
                    .map_err(|e| e.to_string())?,
            )?;
        }
        Ok(())
    })
}

/// A running worker process that lowers the entries it is sent.
struct Session {
    child: Child,
    stdin: std::process::ChildStdin,
    lines: mpsc::Receiver<String>,
    lowered: usize,
    /// Resident memory once the crate is loaded and planned.
    baseline: Option<u64>,
}

/// The compiler keeps memory from every entry a worker lowers, so a worker is
/// replaced once it has grown this much since it loaded the crate (Linux,
/// where its size can be read) ...
const WORKER_RECYCLE_GROWTH: u64 = 2 * 1024 * 1024 * 1024;
/// ... or after this many entries everywhere.
const WORKER_RECYCLE_ENTRIES: usize = 256;

enum Outcome {
    Done(Result<String, String>),
    /// The worker died; the message says how.
    Failed(String),
    /// The entry used up its time budget.
    TimedOut,
    /// The worker outgrew its memory share and was stopped.
    OverMemory,
}

/// A `/proc/meminfo` field in bytes, where the platform exposes it.
fn meminfo_bytes(field: &str) -> Option<u64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    let line = text.lines().find(|l| l.starts_with(field))?;
    let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kib * 1024)
}

const GIB: u64 = 1024 * 1024 * 1024;

/// Resident memory of a process, where the platform exposes it.
fn resident_bytes(pid: u32) -> Option<u64> {
    let statm = std::fs::read_to_string(format!("/proc/{pid}/statm")).ok()?;
    let pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    Some(pages * 4096)
}

impl Session {
    fn start(pool: &Pool) -> Result<Session, String> {
        let Pool {
            worker,
            options,
            package,
            plan,
            startup,
        } = *pool;
        let mut command = Command::new(&worker.exe);
        command
            .arg("__lower")
            .arg("--program-dir")
            .arg(options.program_dir)
            .arg("--package")
            .arg(package.name.to_string())
            .arg("--entry")
            .arg(options.entry.as_arg());
        if let Some(filter) = options.function_filter {
            command.arg("--function").arg(filter);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("cannot start worker {}: {e}", worker.exe.display()))?;
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        let (sender, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        let mut session = Session {
            child,
            stdin,
            lines,
            lowered: 0,
            baseline: None,
        };
        let header = session
            .lines
            .recv_timeout(startup.max(worker.timeout))
            .ok()
            .and_then(|line| serde_json::from_str::<WorkerPlan>(&line).ok());
        let expected: Vec<&str> = plan.iter().map(|e| e.name.as_str()).collect();
        match header {
            Some(header) if header.plan == expected => {
                session.baseline = resident_bytes(session.child.id());
                Ok(session)
            }
            Some(_) => {
                session.kill();
                Err(
                    "the worker planned different entry points (was noirspect rebuilt mid-run?)"
                        .to_string(),
                )
            }
            None => {
                session.kill();
                Err("the worker did not start".to_string())
            }
        }
    }

    /// Lower one entry. The worker is gone after anything but `Done`.
    fn lower(&mut self, index: usize, timeout: Duration, memory_cap: Option<u64>) -> Outcome {
        if writeln!(self.stdin, "{index}")
            .and_then(|_| self.stdin.flush())
            .is_err()
        {
            return Outcome::Failed("the compiler crashed on this entry".to_string());
        }
        let started = std::time::Instant::now();
        loop {
            match self.lines.recv_timeout(Duration::from_secs(1)) {
                Ok(line) => {
                    let Ok(parsed) = serde_json::from_str::<WorkerLine>(&line) else {
                        continue;
                    };
                    if parsed.index == index {
                        return Outcome::Done(match (parsed.ssa, parsed.error) {
                            (Some(ssa), _) => Ok(ssa),
                            (None, error) => Err(error.unwrap_or_default()),
                        });
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if started.elapsed() >= timeout {
                        return Outcome::TimedOut;
                    }
                    if let (Some(cap), Some(used)) = (memory_cap, resident_bytes(self.child.id()))
                        && used > cap
                    {
                        return Outcome::OverMemory;
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Outcome::Failed("the compiler crashed on this entry".to_string());
                }
            }
        }
    }

    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// Whether the worker has grown enough that a fresh one would be cheaper.
    fn worn_out(&self) -> bool {
        let grown = match (self.baseline, resident_bytes(self.child.id())) {
            (Some(base), Some(now)) => now.saturating_sub(base) > WORKER_RECYCLE_GROWTH,
            _ => false,
        };
        self.lowered >= WORKER_RECYCLE_ENTRIES || grown
    }

    fn finish(mut self) {
        drop(self.stdin);
        let _ = self.child.wait();
    }
}

/// Lower `plan` in up to `worker.jobs` long-lived worker processes, handing
/// out one entry at a time so slow entries do not hold up the others. An
/// entry over budget kills its worker and is skipped.
///
/// Some circuits need many gigabytes to compile, and several of them at once
/// can exhaust the machine. Each worker therefore gets a share of memory; an
/// entry that outgrows it is put aside and retried at the end, alone, with
/// most of the memory then available. `--entry-timeout` is the total time an
/// entry may take, so the retry only gets what the first attempt left.
fn lower_in_workers(
    worker: &Worker,
    options: &LoadOptions,
    package: &Package,
    plan: &[PlannedEntry],
    startup: Duration,
) -> Vec<EntrySsa> {
    let jobs = worker.jobs.clamp(1, plan.len().max(1));
    let share = meminfo_bytes("MemTotal:").map(|total| (total / 2 / jobs as u64).max(2 * GIB));
    let all: Vec<(usize, Duration)> = (0..plan.len()).map(|i| (i, worker.timeout)).collect();
    let pool = Pool {
        worker,
        options,
        package,
        plan,
        startup,
    };
    let (mut results, deferred) = lower_pass(&pool, &all, jobs, share.filter(|_| jobs > 1));
    if !deferred.is_empty() {
        let alone = meminfo_bytes("MemAvailable:").map(|available| available / 4 * 3);
        let (retried, still_too_big) = lower_pass(&pool, &deferred, 1, alone);
        for (index, lowered) in retried.into_iter().enumerate() {
            if lowered.is_some() {
                results[index] = lowered;
            }
        }
        for (index, _) in still_too_big {
            let gib = alone.unwrap_or_default() as f64 / GIB as f64;
            results[index] = Some(Err(format!(
                "lowering needed more than {gib:.1} GiB of memory; skipped"
            )));
        }
    }
    plan.iter()
        .zip(results)
        .map(|(entry, ssa)| EntrySsa {
            name: entry.name.clone(),
            is_main: entry.is_main,
            ssa: ssa.unwrap_or_else(|| Err("not lowered".to_string())),
        })
        .collect()
}

type Budgeted = (usize, Duration);

/// What every worker of one package is started with.
#[derive(Clone, Copy)]
struct Pool<'a> {
    worker: &'a Worker,
    options: &'a LoadOptions<'a>,
    package: &'a Package,
    plan: &'a [PlannedEntry],
    /// How long a worker may take to check and plan the package.
    startup: Duration,
}

/// Lower `entries` (plan index, time left) with `jobs` workers; returns the
/// results (indexed like `plan`) and the entries that outgrew `memory_cap`,
/// with the time they have left.
fn lower_pass(
    pool: &Pool,
    entries: &[Budgeted],
    jobs: usize,
    memory_cap: Option<u64>,
) -> (Vec<Option<Result<String, String>>>, Vec<Budgeted>) {
    let (worker, plan) = (pool.worker, pool.plan);
    let timed_out = || {
        format!(
            "lowering took longer than {}s; skipped",
            worker.timeout.as_secs()
        )
    };
    let queue = std::sync::Mutex::new(entries.iter().rev().copied().collect::<Vec<_>>());
    let results = std::sync::Mutex::new(vec![None::<Result<String, String>>; plan.len()]);
    let deferred = std::sync::Mutex::new(Vec::new());
    let fatal = std::sync::Mutex::new(None::<String>);
    std::thread::scope(|scope| {
        for _ in 0..jobs {
            scope.spawn(|| {
                let mut session: Option<Session> = None;
                while let Some((index, budget)) = queue.lock().expect("queue lock").pop() {
                    if let Some(error) = fatal.lock().expect("fatal lock").clone() {
                        results.lock().expect("results lock")[index] = Some(Err(error));
                        continue;
                    }
                    if session.is_none() {
                        match Session::start(pool) {
                            Ok(started) => session = Some(started),
                            Err(error) => {
                                *fatal.lock().expect("fatal lock") = Some(error.clone());
                                results.lock().expect("results lock")[index] = Some(Err(error));
                                continue;
                            }
                        }
                    }
                    let running = session.as_mut().expect("running session");
                    let started = std::time::Instant::now();
                    let outcome = running.lower(index, budget, memory_cap);
                    if std::env::var_os("NOIRSPECT_TRACE").is_some() {
                        let state = match &outcome {
                            Outcome::Done(Ok(_)) => "ok".to_string(),
                            Outcome::Done(Err(e)) | Outcome::Failed(e) => {
                                e.lines().next().unwrap_or_default().to_string()
                            }
                            Outcome::OverMemory => "over memory share".to_string(),
                            Outcome::TimedOut => timed_out(),
                        };
                        let rss =
                            resident_bytes(running.child.id()).unwrap_or_default() / (1024 * 1024);
                        eprintln!(
                            "noirspect: [{index}] {} {:.1}s {rss} MiB: {state}",
                            plan[index].name,
                            started.elapsed().as_secs_f64()
                        );
                    }
                    match outcome {
                        Outcome::Done(lowered) => {
                            running.lowered += 1;
                            if running.worn_out() {
                                session.take().expect("running session").finish();
                            }
                            results.lock().expect("results lock")[index] = Some(lowered);
                        }
                        Outcome::Failed(error) => {
                            session.take().expect("running session").kill();
                            results.lock().expect("results lock")[index] = Some(Err(error));
                        }
                        Outcome::TimedOut => {
                            session.take().expect("running session").kill();
                            results.lock().expect("results lock")[index] = Some(Err(timed_out()));
                        }
                        Outcome::OverMemory => {
                            session.take().expect("running session").kill();
                            match budget.checked_sub(started.elapsed()) {
                                Some(left) if left >= Duration::from_secs(1) => {
                                    deferred.lock().expect("deferred lock").push((index, left));
                                }
                                _ => {
                                    results.lock().expect("results lock")[index] =
                                        Some(Err(timed_out()))
                                }
                            }
                        }
                    }
                }
                if let Some(running) = session {
                    running.finish();
                }
            });
        }
    });
    let mut deferred = deferred.into_inner().expect("deferred lock");
    deferred.sort_unstable_by_key(|(index, _)| *index);
    (results.into_inner().expect("results lock"), deferred)
}

fn display_name(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

/// The crate's functions, sorted by how the analysis can reach them.
struct CrateFunctions {
    /// Constrained, non-generic functions with bodies: lowered on their own.
    concrete: Vec<FuncId>,
    /// Constrained functions that cannot be lowered as `main` (generic, or taking
    /// references or vectors): only reachable through their instances in callers.
    generic_names: BTreeSet<String>,
    /// Test functions, which instantiate generic code with concrete types.
    tests: Vec<FuncId>,
}

fn crate_functions(context: &Context, crate_id: CrateId) -> CrateFunctions {
    let module = crate_to_module(crate_id, &context.def_maps, &context.def_interner, false);
    let mut all = Vec::new();
    collect_functions(&module, &mut all);
    all.sort();
    all.dedup();
    let mut out = CrateFunctions {
        concrete: Vec::new(),
        generic_names: BTreeSet::new(),
        tests: Vec::new(),
    };
    for func in all {
        let interner = &context.def_interner;
        let meta = interner.function_meta(&func);
        let kind = interner
            .function_attributes(&func)
            .function()
            .map(|f| &f.kind);
        let has_body = interner.function(&func).try_as_expr().is_some();
        if matches!(kind, Some(FunctionAttributeKind::Test(_))) {
            out.tests.push(func);
            continue;
        }
        let special = matches!(
            kind,
            Some(
                FunctionAttributeKind::Foreign(_)
                    | FunctionAttributeKind::Builtin(_)
                    | FunctionAttributeKind::Oracle(_)
                    | FunctionAttributeKind::FuzzingHarness(_)
            )
        );
        if special
            || !has_body
            || meta.is_unconstrained()
            || interner.function_modifiers(&func).is_comptime
        {
            continue;
        }
        // A function-typed parameter becomes an opaque value at an entry point, so
        // any constraint made through it (an order check passed in as a closure)
        // would be invisible and the analysis would report it missing.
        let takes_function = meta
            .parameters
            .0
            .iter()
            .any(|(_, typ, _)| matches!(typ.follow_bindings(), Type::Function(..)));
        if takes_function {
            continue;
        }
        let generic = !meta.all_generics.is_empty() || !meta.trait_constraints.is_empty();
        let main_compatible = meta
            .parameters
            .0
            .iter()
            .all(|(_, typ, _)| can_be_main_parameter(typ));
        if !generic && main_compatible {
            out.concrete.push(func);
        } else {
            out.generic_names
                .insert(interner.function_name(&func).to_string());
        }
    }
    out
}

/// `main` cannot take references or vectors; such functions are analyzed
/// through their instances in callers instead.
fn can_be_main_parameter(typ: &Type) -> bool {
    match typ.follow_bindings() {
        Type::Reference(..) | Type::Vector(..) => false,
        Type::Array(_, element) => can_be_main_parameter(&element),
        Type::Tuple(elements) => elements.iter().all(can_be_main_parameter),
        _ => true,
    }
}

fn collect_functions(module: &items::Module, out: &mut Vec<FuncId>) {
    for (_, item) in &module.items {
        collect_item(item, out);
    }
}

fn collect_item(item: &items::Item, out: &mut Vec<FuncId>) {
    match item {
        items::Item::Module(m) => collect_functions(m, out),
        items::Item::Function(f) => out.push(*f),
        items::Item::DataType(t) => {
            t.impls
                .iter()
                .for_each(|i| out.extend(i.methods.iter().map(|(_, f)| *f)));
            t.trait_impls
                .iter()
                .for_each(|i| out.extend(i.methods.iter().copied()));
        }
        items::Item::PrimitiveType(t) => {
            t.impls
                .iter()
                .for_each(|i| out.extend(i.methods.iter().map(|(_, f)| *f)));
            t.trait_impls
                .iter()
                .for_each(|i| out.extend(i.methods.iter().copied()));
        }
        items::Item::Impl(i) => out.extend(i.methods.iter().map(|(_, f)| *f)),
        items::Item::TraitImpl(i) => out.extend(i.methods.iter().copied()),
        _ => {}
    }
}

/// Constrained instantiations of the crate's generic functions in `source`'s SSA.
fn generic_instances(
    context: &Context,
    source: FuncId,
    generic_names: &BTreeSet<String>,
) -> Vec<(FunctionId, String)> {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let program = monomorphize(source, &context.def_interner, false).ok()?;
        let ssa = generate_ssa(program).ok()?;
        Some(
            ssa.functions
                .iter()
                .filter(|(id, f)| {
                    **id != ssa.main_id
                        && generic_names.contains(f.name())
                        && f.to_string().starts_with("acir")
                })
                .map(|(id, f)| (*id, f.name().to_string()))
                .collect::<Vec<_>>(),
        )
    }));
    outcome.ok().flatten().unwrap_or_default()
}

/// Lower `func` to optimized SSA. With `instance`, the SSA function of that id
/// inside `func`'s program becomes the entry point instead of `func` itself, so
/// a generic function is analyzed with its own parameters as circuit inputs.
fn optimized_ssa(
    context: &Context,
    func: FuncId,
    instance: Option<FunctionId>,
    ssa_options: &SsaEvaluatorOptions,
) -> Result<String, String> {
    let file_manager = context.file_manager.clone();
    let outcome = catch_unwind(AssertUnwindSafe(|| -> Result<String, String> {
        let program = monomorphize(func, &context.def_interner, false)
            .map_err(|e| CustomDiagnostic::from(e).message)?;
        let mut ssa = generate_ssa(program).map_err(|e| CustomDiagnostic::from(e).message)?;
        if let Some(instance) = instance {
            ssa.main_id = instance;
        }
        let builder =
            SsaBuilder::from_ssa(ssa, SsaLogging::None, false, false, Some(&file_manager));
        // With a generic instance standing in for `main`, `&mut` parameters stay
        // memory, which this pass asserts is gone. It only marks array writes
        // that may happen in place, which the rules do not look at.
        let passes: Vec<_> = primary_passes(ssa_options)
            .into_iter()
            .filter(|pass| instance.is_none() || pass.msg() != "Mutable Array Set Optimizations")
            .collect();
        let builder = builder
            .run_passes(&passes)
            .map_err(|e| CustomDiagnostic::from(e).message)?;
        Ok(builder.ssa().print_with(Some(&file_manager)).to_string())
    }));
    match outcome {
        Ok(result) => result,
        Err(panic) => {
            let message = panic
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "unknown panic".to_string());
            Err(format!("compiler panicked: {message}"))
        }
    }
}

fn render_diagnostics(diagnostics: &[&CustomDiagnostic], file_manager: &FileManager) -> String {
    diagnostics
        .iter()
        .map(|d| {
            let file = file_manager
                .path(d.file)
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            format!("  {file}: {}", d.message)
        })
        .collect::<Vec<_>>()
        .join("\n")
}
