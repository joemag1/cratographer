//! Rust analyzer integration module
//!
//! This module provides integration with rust-analyzer's IDE APIs for semantic analysis
//! of Rust code. It handles project loading, symbol lookups, and other code intelligence
//! features needed by Cratographer.

use ra_ap_ide::{AnalysisHost, SymbolKind as RaSymbolKind};
use ra_ap_paths::{AbsPathBuf, Utf8PathBuf};
use ra_ap_project_model::CargoConfig;
use std::path::PathBuf;

/// Search mode for symbol lookup
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SearchMode {
    /// Exact match - symbol name must match exactly
    Exact,
    /// Fuzzy match - allows approximate matches (default)
    #[default]
    Fuzzy,
    /// Prefix match - symbol name must start with the search string
    Prefix,
}

/// Filter for symbol kind
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SymbolFilter {
    /// Only type symbols (structs, enums, traits, type aliases)
    Types,
    /// Only implementation blocks
    Implementations,
    /// Only functions and methods
    Functions,
    /// All symbols (no filtering) - default
    #[default]
    All,
}

/// Options for symbol search
#[derive(Debug, Clone, Default)]
pub struct SearchOptions {
    /// Search mode (exact, fuzzy, or prefix)
    pub mode: SearchMode,
    /// Include symbols from library dependencies
    pub include_library: bool,
    /// Filter by symbol kind
    pub filter: SymbolFilter,
}

/// Error types for analyzer operations
#[derive(Debug)]
pub enum AnalyzerError {
    /// Failed to load the project
    ProjectLoadError(String),
    /// Failed to find project manifest
    ManifestNotFound(String),
    /// IO error
    IoError(std::io::Error),
    /// Canceled operation
    Canceled,
    /// Unknown error
    Other(String),
}

impl std::fmt::Display for AnalyzerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnalyzerError::ProjectLoadError(msg) => write!(f, "Project load error: {}", msg),
            AnalyzerError::ManifestNotFound(msg) => write!(f, "Manifest not found: {}", msg),
            AnalyzerError::IoError(err) => write!(f, "IO error: {}", err),
            AnalyzerError::Canceled => write!(f, "Operation was canceled"),
            AnalyzerError::Other(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl std::error::Error for AnalyzerError {}

impl From<std::io::Error> for AnalyzerError {
    fn from(err: std::io::Error) -> Self {
        AnalyzerError::IoError(err)
    }
}

/// Main analyzer interface for Cratographer
///
/// This wraps rust-analyzer's AnalysisHost and provides a simpler API
/// for the operations we need.
pub struct Analyzer {
    host: AnalysisHost,
    vfs: ra_ap_vfs::Vfs,
    loader: Option<ra_ap_vfs_notify::NotifyHandle>,
}

impl Analyzer {
    /// Create a new analyzer instance
    pub fn new() -> Self {
        Self {
            host: AnalysisHost::new(None), // No LRU capacity limit
            vfs: ra_ap_vfs::Vfs::default(),
            loader: None,
        }
    }

    /// Load a Rust project from the given path
    ///
    /// This will:
    /// 1. Find the Cargo.toml manifest
    /// 2. Load the project workspace
    /// 3. Set up the analysis database with VFS and CrateGraph
    /// 4. Enable file watching for incremental updates
    ///
    /// Returns a receiver channel for file change notifications
    pub fn load_project(&mut self, project_path: impl Into<PathBuf>) -> Result<crossbeam_channel::Receiver<ra_ap_vfs::loader::Message>, AnalyzerError> {
        use crossbeam_channel::unbounded;
        use ra_ap_ide_db::{ChangeWithProcMacros, RootDatabase};
        use ra_ap_load_cargo::ProjectFolders;
        use ra_ap_project_model::{ProjectManifest, ProjectWorkspace};
        use ra_ap_vfs::loader::{Handle, LoadingProgress};

        let project_path: PathBuf = project_path.into();
        let canonical_path = project_path
            .canonicalize()
            .map_err(|e| AnalyzerError::ManifestNotFound(format!("{}: {}", project_path.display(), e)))?;

        // Convert to Utf8PathBuf as required by rust-analyzer
        let utf8_path = Utf8PathBuf::from_path_buf(canonical_path)
            .map_err(|p| AnalyzerError::ManifestNotFound(format!("Path is not valid UTF-8: {}", p.display())))?;

        let abs_path = AbsPathBuf::assert(utf8_path);

        // Create file watcher
        let (sender, receiver) = unbounded();
        let mut loader = ra_ap_vfs_notify::NotifyHandle::spawn(sender);

        // Build cargo config
        let mut cargo_config = CargoConfig::default();
        cargo_config.all_targets = true;

        // Discover and load the workspace
        let progress = |_msg: String| {};
        let manifest = ProjectManifest::discover_single(&abs_path)
            .map_err(|e| AnalyzerError::ProjectLoadError(format!("{:?}", e)))?;
        let mut workspace = ProjectWorkspace::load(manifest, &cargo_config, &progress)
            .map_err(|e| AnalyzerError::ProjectLoadError(format!("{:?}", e)))?;

        // Load build scripts if needed
        let build_scripts = workspace.run_build_scripts(&cargo_config, &progress)
            .map_err(|e| AnalyzerError::ProjectLoadError(format!("{:?}", e)))?;
        workspace.set_build_scripts(build_scripts);

        // Create database
        let lru_cap = std::env::var("RA_LRU_CAP").ok().and_then(|it| it.parse::<u16>().ok());
        let mut db = RootDatabase::new(lru_cap);

        // Build crate graph and load files into VFS
        let (crate_graph, _proc_macros) = workspace.to_crate_graph(
            &mut |path: &ra_ap_paths::AbsPath| {
                let contents = loader.load_sync(path);
                let vfs_path = ra_ap_vfs::VfsPath::from(path.to_path_buf());
                self.vfs.set_file_contents(vfs_path.clone(), contents);
                self.vfs.file_id(&vfs_path).and_then(|(file_id, excluded)| {
                    (excluded == ra_ap_vfs::FileExcluded::No).then_some(file_id)
                })
            },
            &Default::default(),
        );

        // Build project folders with watch indices
        let project_folders = ProjectFolders::new(std::slice::from_ref(&workspace), &[], None);

        // Configure loader with watching enabled
        loader.set_config(ra_ap_vfs::loader::Config {
            load: project_folders.load,
            watch: project_folders.watch,  // Enable watching (not empty like load_workspace_at)
            version: 0,
        });

        // Process initial load messages
        let mut analysis_change = ChangeWithProcMacros::default();
        db.enable_proc_attr_macros();

        for task in &receiver {
            match task {
                ra_ap_vfs::loader::Message::Progress { n_done, .. } => {
                    if n_done == LoadingProgress::Finished {
                        break;
                    }
                }
                ra_ap_vfs::loader::Message::Loaded { files } | ra_ap_vfs::loader::Message::Changed { files } => {
                    for (path, contents) in files {
                        self.vfs.set_file_contents(path.into(), contents);
                    }
                }
            }
        }

        // Apply initial changes to database
        let changes = self.vfs.take_changes();
        for (_, file) in changes {
            if let ra_ap_vfs::Change::Create(v, _) | ra_ap_vfs::Change::Modify(v, _) = file.change {
                if let Ok(text) = String::from_utf8(v) {
                    analysis_change.change_file(file.file_id, Some(text));
                }
            }
        }

        let source_roots = project_folders.source_root_config.partition(&self.vfs);
        analysis_change.set_roots(source_roots);
        analysis_change.set_crate_graph(crate_graph);

        db.apply_change(analysis_change);

        // Create AnalysisHost from the loaded database
        self.host = AnalysisHost::with_database(db);

        // Store loader for future file watching
        self.loader = Some(loader);

        Ok(receiver)
    }

    /// Find all occurrences of a symbol by name
    ///
    /// This searches across the entire workspace for symbols matching the given name.
    pub fn find_symbol(&self, name: &str, options: &SearchOptions) -> Result<Vec<SymbolInfo>, AnalyzerError> {
        let analysis = self.host.analysis();

        // Build the query with the specified options
        let mut query = ra_ap_ide::Query::new(name.to_string());

        // Apply search mode
        match options.mode {
            SearchMode::Exact => { query.exact(); },
            SearchMode::Fuzzy => { query.fuzzy(); },
            SearchMode::Prefix => { query.prefix(); },
        }

        // Apply library inclusion
        if options.include_library {
            query.libs();
        }

        // Apply types-only filter if filtering by Types
        if options.filter == SymbolFilter::Types {
            query.only_types();
        }

        // Use symbol_search to find all symbols matching the name
        // Limit to 32 results
        let symbols = analysis.symbol_search(query, 32)
            .map_err(|_| AnalyzerError::Canceled)?;

        // Convert to our SymbolInfo type, filtering by symbol kind
        let results = symbols
            .into_iter()
            .filter_map(|nav| {
                // Filter to only include symbol kinds we care about
                let kind = convert_symbol_kind(nav.kind.unwrap_or(RaSymbolKind::Module))?;

                // Apply post-search filtering based on SymbolFilter
                match options.filter {
                    SymbolFilter::Types => {
                        // Types filter is handled by query.only_types() above
                        // This should already be filtered, but we can double-check
                    }
                    SymbolFilter::Implementations => {
                        // Only keep Impl blocks
                        if kind != SymbolKind::Impl {
                            return None;
                        }
                    }
                    SymbolFilter::Functions => {
                        // Only keep Function and Method
                        if !matches!(kind, SymbolKind::Function | SymbolKind::Method) {
                            return None;
                        }
                    }
                    SymbolFilter::All => {
                        // No filtering
                    }
                }

                let file_id = nav.file_id;
                let range = nav.full_range;

                // Try to get the file path from VFS
                let file_path = self.vfs.file_path(file_id);
                let path_str = file_path.as_path()
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| format!("{:?}", file_id));

                // Get file text to compute line numbers
                let (start_line, end_line) = if let Some(text) = analysis.file_text(file_id).ok() {
                    let line_index = ra_ap_ide::LineIndex::new(&text);
                    let start = line_index.line_col(range.start());
                    let end = line_index.line_col(range.end());
                    (start.line, end.line)
                } else {
                    (0, 0)
                };

                // Extract documentation
                let documentation = nav.docs.as_ref().map(|d| d.as_str().to_string());

                Some(SymbolInfo {
                    name: nav.name.to_string(),
                    kind,
                    file_path: path_str,
                    start_line,
                    end_line,
                    documentation,
                })
            })
            .collect();

        Ok(results)
    }

    /// List all symbols defined in a file
    ///
    /// Given a file path, this returns all symbols defined in that file.
    pub fn enumerate_file(&self, file_path: &str) -> Result<Vec<SymbolInfo>, AnalyzerError> {
        // Convert file path to FileId
        let abs_path = AbsPathBuf::assert(Utf8PathBuf::from(file_path));
        let vfs_path = ra_ap_vfs::VfsPath::from(abs_path);

        let (file_id, _) = self.vfs.file_id(&vfs_path)
            .ok_or_else(|| AnalyzerError::Other(format!("File not found in VFS: {}", file_path)))?;

        let analysis = self.host.analysis();

        // Use file_structure to get all symbols in the file
        let config = ra_ap_ide::FileStructureConfig {
            exclude_locals: true,
        };
        let structure = analysis.file_structure(&config, file_id).map_err(|_| AnalyzerError::Canceled)?;

        // Get file text to compute line/col
        let text = analysis.file_text(file_id).map_err(|_| AnalyzerError::Canceled)?;
        let line_index = ra_ap_ide::LineIndex::new(&text);

        // Convert to our SymbolInfo type, filtering based on SymbolKind
        let results = structure
            .into_iter()
            .filter_map(|node| {
                // Only process nodes that have a SymbolKind
                // Skip ExternBlock and Region variants
                if let ra_ap_ide::StructureNodeKind::SymbolKind(ra_kind) = node.kind {
                    // convert_symbol_kind filters to only include the symbol kinds we care about
                    convert_symbol_kind(ra_kind).map(|kind| {
                        let start = line_index.line_col(node.node_range.start());
                        let end = line_index.line_col(node.node_range.end());

                        SymbolInfo {
                            name: node.label.clone(),
                            kind,
                            file_path: file_path.to_string(),
                            start_line: start.line,
                            end_line: end.line,
                            documentation: node.detail.clone(),
                        }
                    })
                } else {
                    None
                }
            })
            .collect();

        Ok(results)
    }

    /// Apply incremental file changes to the analysis host
    ///
    /// This is called by the background watcher task when files change on disk.
    /// It updates the VFS and applies the changes incrementally to the index.
    pub fn apply_file_changes(
        &mut self,
        files: Vec<(ra_ap_paths::AbsPathBuf, Option<Vec<u8>>)>
    ) -> Result<(), AnalyzerError> {
        use ra_ap_ide_db::ChangeWithProcMacros;

        // Update VFS with new file contents
        for (path, contents) in files {
            let vfs_path = ra_ap_vfs::VfsPath::from(path);
            self.vfs.set_file_contents(vfs_path, contents);
        }

        // Take accumulated changes from VFS
        let changes = self.vfs.take_changes();
        if changes.is_empty() {
            return Ok(());
        }

        // Build ChangeWithProcMacros from VFS changes
        let mut analysis_change = ChangeWithProcMacros::default();
        for (_, file) in changes {
            match file.change {
                ra_ap_vfs::Change::Create(v, _) | ra_ap_vfs::Change::Modify(v, _) => {
                    if let Ok(text) = String::from_utf8(v) {
                        analysis_change.change_file(file.file_id, Some(text));
                    }
                }
                ra_ap_vfs::Change::Delete => {
                    analysis_change.change_file(file.file_id, None);
                }
            }
        }

        // Apply changes to analysis host
        self.host.apply_change(analysis_change);

        Ok(())
    }
}

impl Default for Analyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert rust-analyzer's SymbolKind to our SymbolKind
/// Returns None for symbol kinds we don't care about
fn convert_symbol_kind(kind: RaSymbolKind) -> Option<SymbolKind> {
    match kind {
        RaSymbolKind::Const => Some(SymbolKind::Const),
        RaSymbolKind::Enum => Some(SymbolKind::Enum),
        RaSymbolKind::Function => Some(SymbolKind::Function),
        RaSymbolKind::Impl => Some(SymbolKind::Impl),
        RaSymbolKind::Method => Some(SymbolKind::Method),
        RaSymbolKind::Module => Some(SymbolKind::Module),
        RaSymbolKind::Static => Some(SymbolKind::Static),
        RaSymbolKind::Struct => Some(SymbolKind::Struct),
        RaSymbolKind::Trait => Some(SymbolKind::Trait),
        RaSymbolKind::TypeAlias => Some(SymbolKind::TypeAlias),
        _ => None,
    }
}

/// Information about a symbol in the codebase
#[derive(Debug, Clone)]
pub struct SymbolInfo {
    pub name: String,
    pub kind: SymbolKind,
    pub file_path: String,
    pub start_line: u32,
    pub end_line: u32,
    pub documentation: Option<String>,
}

/// Kind of symbol - only includes symbol kinds we care about
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolKind {
    Const,
    Enum,
    Function,
    Impl,
    Method,
    Module,
    Static,
    Struct,
    Trait,
    TypeAlias,
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyzer_creation() {
        let _analyzer = Analyzer::new();
        // Just verify we can create an analyzer
    }

    #[test]
    fn test_load_and_find_symbol() {
        let mut analyzer = Analyzer::new();

        // Load the current project (cratographer itself)
        let result = analyzer.load_project(".");
        assert!(result.is_ok(), "Failed to load project: {:?}", result.err());

        // Try to find the "Analyzer" struct we just defined
        let options = SearchOptions::default();
        let symbols = analyzer.find_symbol("Analyzer", &options);
        assert!(symbols.is_ok(), "Failed to search for symbols: {:?}", symbols.err());

        let symbols = symbols.unwrap();
        println!("Found {} symbols matching 'Analyzer'", symbols.len());

        // We should find at least our Analyzer struct
        let analyzer_struct = symbols.iter().find(|s| {
            s.name == "Analyzer" && matches!(s.kind, SymbolKind::Struct)
        });

        assert!(
            analyzer_struct.is_some(),
            "Should find the Analyzer struct. Found symbols: {:?}",
            symbols
        );

        for sym in symbols.iter() {
            println!("Found Analyzer: {:?}", sym);
        }
    }

    #[test]
    fn test_find_cratographer_server() {
        let mut analyzer = Analyzer::new();

        // Load the current project
        let result = analyzer.load_project(".");
        assert!(result.is_ok(), "Failed to load project: {:?}", result.err());

        // Try to find the CratographerServer struct from main.rs
        let options = SearchOptions::default();
        let symbols = analyzer.find_symbol("CratographerServer", &options);
        assert!(symbols.is_ok(), "Failed to search for symbols: {:?}", symbols.err());

        let symbols = symbols.unwrap();
        println!("Found {} symbols matching 'CratographerServer'", symbols.len());

        // We should find the CratographerServer struct
        let server_struct = symbols.iter().find(|s| {
            s.name == "CratographerServer" && matches!(s.kind, SymbolKind::Struct)
        });

        assert!(
            server_struct.is_some(),
            "Should find the CratographerServer struct. Found symbols: {:?}",
            symbols
        );

        for sym in symbols.iter() {
            println!("Found AnalyzerServer: {:?}", sym);
        }
    }

    #[test]
    fn test_exact_search_vs_prefix() {
        let mut analyzer = Analyzer::new();

        // Load the current project
        let result = analyzer.load_project(".");
        assert!(result.is_ok(), "Failed to load project: {:?}", result.err());

        // Test exact search - should find only "Analyzer", not "AnalyzerError"
        let exact_options = SearchOptions {
            mode: SearchMode::Exact,
            include_library: false,
            filter: SymbolFilter::All,
        };
        let exact_results = analyzer.find_symbol("Analyzer", &exact_options);
        assert!(exact_results.is_ok(), "Exact search failed: {:?}", exact_results.err());

        let exact_symbols = exact_results.unwrap();
        println!("Exact search found {} symbols", exact_symbols.len());
        for sym in &exact_symbols {
            println!("  - {}: {:?}", sym.name, sym.kind);
        }

        // Exact search may find both "Analyzer" struct and "analyzer" module (case-insensitive)
        // Let's verify we find the Analyzer struct specifically
        let analyzer_struct = exact_symbols.iter().find(|s| {
            s.name == "Analyzer" && matches!(s.kind, SymbolKind::Struct)
        });
        assert!(
            analyzer_struct.is_some(),
            "Exact search should find the Analyzer struct"
        );

        // Should NOT find AnalyzerError with exact search
        let has_analyzer_error = exact_symbols.iter().any(|s| s.name == "AnalyzerError");
        assert!(
            !has_analyzer_error,
            "Exact search should not find AnalyzerError"
        );

        // Test prefix search - should find both "Analyzer" and "AnalyzerError"
        let prefix_options = SearchOptions {
            mode: SearchMode::Prefix,
            include_library: false,
            filter: SymbolFilter::All,
        };
        let prefix_results = analyzer.find_symbol("Analyzer", &prefix_options);
        assert!(prefix_results.is_ok(), "Prefix search failed: {:?}", prefix_results.err());

        let prefix_symbols = prefix_results.unwrap();
        println!("Prefix search found {} symbols", prefix_symbols.len());
        for sym in &prefix_symbols {
            println!("  - {}: {:?}", sym.name, sym.kind);
        }

        // Should find at least 2 results (Analyzer and AnalyzerError, possibly also analyzer module)
        assert!(
            prefix_symbols.len() >= 2,
            "Prefix search should find at least 2 results, found {}: {:?}",
            prefix_symbols.len(),
            prefix_symbols
        );

        // Verify we find both Analyzer and AnalyzerError
        let has_analyzer = prefix_symbols.iter().any(|s| {
            s.name == "Analyzer" && matches!(s.kind, SymbolKind::Struct)
        });
        let has_analyzer_error = prefix_symbols.iter().any(|s| {
            s.name == "AnalyzerError" && matches!(s.kind, SymbolKind::Enum)
        });

        assert!(has_analyzer, "Prefix search should find Analyzer struct");
        assert!(has_analyzer_error, "Prefix search should find AnalyzerError enum");
    }

    #[test]
    fn test_search_with_library_dependencies() {
        let mut analyzer = Analyzer::new();

        // Load the current project
        let result = analyzer.load_project(".");
        assert!(result.is_ok(), "Failed to load project: {:?}", result.err());

        // Search for HashMap without including libraries
        let no_lib_options = SearchOptions {
            mode: SearchMode::Exact,
            include_library: false,
            filter: SymbolFilter::All,
        };
        let no_lib_results = analyzer.find_symbol("HashMap", &no_lib_options);
        assert!(no_lib_results.is_ok(), "Search without library failed: {:?}", no_lib_results.err());

        let no_lib_symbols = no_lib_results.unwrap();
        println!("Search without library found {} HashMap symbols", no_lib_symbols.len());

        // Search for HashMap with libraries included
        let with_lib_options = SearchOptions {
            mode: SearchMode::Exact,
            include_library: true,
            filter: SymbolFilter::All,
        };
        let with_lib_results = analyzer.find_symbol("HashMap", &with_lib_options);
        assert!(with_lib_results.is_ok(), "Search with library failed: {:?}", with_lib_results.err());

        let with_lib_symbols = with_lib_results.unwrap();
        println!("Search with library found {} HashMap symbols", with_lib_symbols.len());
        for sym in with_lib_symbols.iter().take(5) {
            println!("  - {} at {}", sym.name, sym.file_path);
        }

        // Should find HashMap from std library when including libraries
        assert!(
            with_lib_symbols.len() > no_lib_symbols.len(),
            "Including libraries should find more symbols. Without lib: {}, with lib: {}",
            no_lib_symbols.len(),
            with_lib_symbols.len()
        );

        // Should find at least one HashMap (from std::collections)
        assert!(
            with_lib_symbols.len() > 0,
            "Should find HashMap in standard library"
        );

        // Verify at least one is from std/core
        let has_std_hashmap = with_lib_symbols.iter().any(|s| {
            s.file_path.contains("std") || s.file_path.contains("hashbrown") || s.file_path.contains("collections")
        });
        assert!(
            has_std_hashmap,
            "Should find HashMap from standard library or hashbrown crate"
        );
    }

    #[test]
    fn test_enumerate_analyzer_file() {
        let mut analyzer = Analyzer::new();

        // Load the current project
        let result = analyzer.load_project(".");
        assert!(result.is_ok(), "Failed to load project: {:?}", result.err());

        // Get the absolute path to analyzer.rs
        let analyzer_path = std::env::current_dir()
            .expect("Failed to get current directory")
            .join("src/analyzer.rs")
            .canonicalize()
            .expect("Failed to canonicalize analyzer.rs path");

        // Enumerate symbols in analyzer.rs
        let symbols = analyzer.enumerate_file(analyzer_path.to_str().unwrap());
        assert!(symbols.is_ok(), "Failed to enumerate analyzer.rs: {:?}", symbols.err());

        let symbols = symbols.unwrap();
        println!("Found {} symbols in analyzer.rs", symbols.len());
        for sym in &symbols {
            println!("  - {} ({:?}) at lines {}-{}", sym.name, sym.kind, sym.start_line, sym.end_line);
        }

        // Verify we found expected enums with correct kind
        let expected_enums = ["SearchMode", "AnalyzerError", "SymbolKind"];
        for expected in &expected_enums {
            let found = symbols.iter().any(|s| {
                s.name == *expected && s.kind == SymbolKind::Enum
            });
            assert!(
                found,
                "Should find {} as Enum in analyzer.rs",
                expected
            );
        }

        // Verify we found expected structs with correct kind
        let expected_structs = ["SearchOptions", "Analyzer", "SymbolInfo"];
        for expected in &expected_structs {
            let found = symbols.iter().any(|s| {
                s.name == *expected && s.kind == SymbolKind::Struct
            });
            assert!(
                found,
                "Should find {} as Struct in analyzer.rs",
                expected
            );
        }

        // Verify we found expected methods
        let expected_methods = ["find_symbol", "enumerate_file", "load_project"];
        for expected in &expected_methods {
            let found = symbols.iter().any(|s| {
                s.name == *expected && s.kind == SymbolKind::Method
            });
            assert!(
                found,
                "Should find {} as Method in analyzer.rs",
                expected
            );
        }

        // Verify we found expected functions
        let expected_functions = ["new", "convert_symbol_kind", "default"];
        for expected in &expected_functions {
            let found = symbols.iter().any(|s| {
                s.name == *expected && s.kind == SymbolKind::Function
            });
            assert!(
                found,
                "Should find {} as Function in analyzer.rs",
                expected
            );
        }

        // Verify we found impl blocks
        let has_impl = symbols.iter().any(|s| s.kind == SymbolKind::Impl);
        assert!(has_impl, "Should find at least one Impl block in analyzer.rs");
    }
}
