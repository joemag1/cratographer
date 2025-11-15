//! Rust analyzer integration module
//!
//! This module provides integration with rust-analyzer's IDE APIs for semantic analysis
//! of Rust code. It handles project loading, symbol lookups, and other code intelligence
//! features needed by Cratographer.

use ra_ap_ide::{AnalysisHost, SymbolKind as RaSymbolKind};
use ra_ap_load_cargo::{load_workspace_at, LoadCargoConfig, ProcMacroServerChoice};
use ra_ap_paths::{AbsPathBuf, Utf8PathBuf};
use ra_ap_project_model::CargoConfig;
use std::path::PathBuf;

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
}

impl Analyzer {
    /// Create a new analyzer instance
    pub fn new() -> Self {
        Self {
            host: AnalysisHost::new(None), // No LRU capacity limit
            vfs: ra_ap_vfs::Vfs::default(),
        }
    }

    /// Load a Rust project from the given path
    ///
    /// This will:
    /// 1. Find the Cargo.toml manifest
    /// 2. Load the project workspace
    /// 3. Set up the analysis database with VFS and CrateGraph
    pub fn load_project(&mut self, project_path: impl Into<PathBuf>) -> Result<(), AnalyzerError> {
        let project_path: PathBuf = project_path.into();
        let canonical_path = project_path
            .canonicalize()
            .map_err(|e| AnalyzerError::ManifestNotFound(format!("{}: {}", project_path.display(), e)))?;

        // Convert to Utf8PathBuf as required by rust-analyzer
        let utf8_path = Utf8PathBuf::from_path_buf(canonical_path)
            .map_err(|p| AnalyzerError::ManifestNotFound(format!("Path is not valid UTF-8: {}", p.display())))?;

        let abs_path = AbsPathBuf::assert(utf8_path);

        // Use load_workspace_at helper to load the project
        let cargo_config = CargoConfig::default();
        let load_config = LoadCargoConfig {
            load_out_dirs_from_check: true,
            with_proc_macro_server: ProcMacroServerChoice::None,
            prefill_caches: false,
        };

        let progress = |_msg: String| {}; // No-op progress callback

        let (db, vfs, _) = load_workspace_at(
            abs_path.as_ref(),
            &cargo_config,
            &load_config,
            &progress,
        ).map_err(|e| AnalyzerError::ProjectLoadError(format!("{:?}", e)))?;

        // Create AnalysisHost from the loaded database
        self.host = AnalysisHost::with_database(db);
        self.vfs = vfs;

        Ok(())
    }

    /// Find all occurrences of a symbol by name
    ///
    /// This searches across the entire workspace for symbols matching the given name.
    pub fn find_symbol(&self, name: &str) -> Result<Vec<SymbolInfo>, AnalyzerError> {
        let analysis = self.host.analysis();

        // Use symbol_search to find all symbols matching the name
        // Limit to 100 results
        let symbols = analysis.symbol_search(
            ra_ap_ide::Query::new(name.to_string()),
            100
        ).map_err(|_| AnalyzerError::Canceled)?;

        // Convert to our SymbolInfo type
        let results = symbols
            .into_iter()
            .map(|nav| {
                let file_id = nav.file_id;
                let range = nav.focus_range.unwrap_or(nav.full_range);

                // Try to get the file path from VFS
                let file_path = self.vfs.file_path(file_id);
                let path_str = file_path.as_path()
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| format!("{:?}", file_id));

                // Get file text to compute line/col
                let text = analysis.file_text(file_id).ok();
                let line_col = if let Some(text) = text {
                    let line_index = ra_ap_ide::LineIndex::new(&text);
                    line_index.line_col(range.start())
                } else {
                    ra_ap_ide::LineCol { line: 0, col: 0 }
                };

                SymbolInfo {
                    name: nav.name.to_string(),
                    kind: convert_symbol_kind(nav.kind.unwrap_or(RaSymbolKind::Module)),
                    file_path: path_str,
                    line: line_col.line,
                    column: line_col.col,
                    documentation: None, // TODO: Extract documentation
                }
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
            exclude_locals: false,
        };
        let structure = analysis.file_structure(&config, file_id).map_err(|_| AnalyzerError::Canceled)?;

        // Get file text to compute line/col
        let text = analysis.file_text(file_id).map_err(|_| AnalyzerError::Canceled)?;
        let line_index = ra_ap_ide::LineIndex::new(&text);

        // Convert to our SymbolInfo type
        let results = structure
            .into_iter()
            .map(|node| {
                let line_col = line_index.line_col(node.node_range.start());

                SymbolInfo {
                    name: node.label.clone(),
                    kind: SymbolKind::from_str(&format!("{:?}", node.kind)),
                    file_path: file_path.to_string(),
                    line: line_col.line,
                    column: line_col.col,
                    documentation: None,
                }
            })
            .collect();

        Ok(results)
    }
}

impl Default for Analyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert rust-analyzer's SymbolKind to our SymbolKind
fn convert_symbol_kind(kind: RaSymbolKind) -> SymbolKind {
    match kind {
        RaSymbolKind::Function => SymbolKind::Function,
        RaSymbolKind::Struct => SymbolKind::Struct,
        RaSymbolKind::Enum => SymbolKind::Enum,
        RaSymbolKind::Trait => SymbolKind::Trait,
        RaSymbolKind::Module => SymbolKind::Module,
        RaSymbolKind::Const => SymbolKind::Const,
        RaSymbolKind::Static => SymbolKind::Static,
        RaSymbolKind::TypeAlias => SymbolKind::TypeAlias,
        RaSymbolKind::Method => SymbolKind::Method,
        RaSymbolKind::Field => SymbolKind::Field,
        _ => SymbolKind::Other,
    }
}

/// Information about a symbol in the codebase
#[derive(Debug, Clone)]
pub struct SymbolInfo {
    pub name: String,
    pub kind: SymbolKind,
    pub file_path: String,
    pub line: u32,
    pub column: u32,
    pub documentation: Option<String>,
}

/// Kind of symbol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolKind {
    Function,
    Struct,
    Enum,
    Trait,
    Module,
    Const,
    Static,
    TypeAlias,
    Method,
    Field,
    Other,
}

impl SymbolKind {
    fn from_str(s: &str) -> Self {
        match s {
            "Function" => SymbolKind::Function,
            "Struct" => SymbolKind::Struct,
            "Enum" => SymbolKind::Enum,
            "Trait" => SymbolKind::Trait,
            "Module" => SymbolKind::Module,
            "Const" => SymbolKind::Const,
            "Static" => SymbolKind::Static,
            "TypeAlias" => SymbolKind::TypeAlias,
            "Method" => SymbolKind::Method,
            "Field" => SymbolKind::Field,
            _ => SymbolKind::Other,
        }
    }
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
        let symbols = analyzer.find_symbol("Analyzer");
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
        let symbols = analyzer.find_symbol("CratographerServer");
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
}
