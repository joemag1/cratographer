mod analyzer;

use analyzer::{Analyzer, SearchMode, SearchOptions, SymbolFilter};
use rmcp::{
    handler::server::{
        router::tool::ToolRouter,
        wrapper::Parameters,
    },
    model::{CallToolResult, Content, ErrorCode, ErrorData as McpError, Implementation, ProtocolVersion, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router, ServerHandler, ServiceExt,
    transport::stdio,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::{Arc, Mutex};

/// Parameters for the find_symbol tool
#[derive(Serialize, Deserialize, JsonSchema)]
struct FindSymbolParams {
    /// The name of the symbol to search for
    name: String,
    /// Search mode: "exact", "fuzzy", or "prefix" (default: "fuzzy")
    #[serde(default)]
    mode: Option<String>,
    /// Whether to include library symbols in the search (default: false)
    #[serde(default)]
    include_library: Option<bool>,
    /// Filter by symbol kind: "types", "implementations", "functions", or "all" (default: "all")
    #[serde(default)]
    filter: Option<String>,
}

/// Parameters for the enumerate_file tool
#[derive(Serialize, Deserialize, JsonSchema)]
struct EnumerateFileParams {
    /// The absolute path to the file to enumerate
    file_path: String,
}

/// Spawn background task to watch for file changes and update the index
fn spawn_file_watcher(
    analyzer: Arc<Mutex<Analyzer>>,
    receiver: crossbeam_channel::Receiver<ra_ap_vfs::loader::Message>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Check if we're in a tokio runtime context
    let _handle = tokio::runtime::Handle::try_current()
        .map_err(|_| "No tokio runtime available")?;

    tokio::spawn(async move {
        use ra_ap_vfs::loader::Message;

        loop {
            // Block on channel receive (runs in tokio threadpool)
            let msg = match receiver.recv() {
                Ok(msg) => msg,
                Err(_) => {
                    eprintln!("File watcher channel closed");
                    break;
                }
            };

            match msg {
                Message::Changed { files } => {
                    // Apply incremental changes
                    let mut analyzer = analyzer.lock().unwrap();
                    if let Err(e) = analyzer.apply_file_changes(files) {
                        eprintln!("Error applying file changes: {}", e);
                    }
                }
                Message::Progress { .. } => {
                    // Ignore progress messages during incremental updates
                }
                Message::Loaded { .. } => {
                    // Initial load messages, ignore (already processed during init)
                }
            }
        }
    });

    Ok(())
}

/// Cratographer MCP Server
/// Provides tools for indexing and querying Rust code symbols
#[derive(Clone)]
struct CratographerServer {
    tool_router: ToolRouter<Self>,
    analyzer: Arc<Mutex<Analyzer>>,
}

#[tool_router]
impl CratographerServer {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // Initialize the analyzer and load the current project
        let mut analyzer = Analyzer::new();

        // Load the current directory as the project
        // Fail initialization if project loading fails
        let receiver = analyzer.load_project(".")?;

        // Perform a warm-up query to force everything to load
        // This helps ensure the analyzer is fully initialized and caches are populated
        let warmup_options = SearchOptions {
            mode: SearchMode::Exact,
            include_library: true,
            filter: SymbolFilter::Types,
        };
        if let Err(e) = analyzer.find_symbol("HashMap", &warmup_options) {
            eprintln!("Warning: Warm-up query failed: {}", e);
        }

        let analyzer = Arc::new(Mutex::new(analyzer));

        // Spawn file watcher task with the receiver
        match spawn_file_watcher(analyzer.clone(), receiver) {
            Ok(_) => eprintln!("File watcher initialized"),
            Err(e) => eprintln!("Warning: Could not start file watcher: {}", e),
        }

        Ok(Self {
            tool_router: Self::tool_router(),
            analyzer,
        })
    }

    /// Find all occurrences of a symbol by name across the indexed codebase
    #[tool(description = "Find all occurrences of a Rust symbol (struct, enum, trait, function, method, impl) by name. \
            Searches both project and library files. Can apply symbol filter: all, types, functions, or implementations.")]
    async fn find_symbol(&self, params: Parameters<FindSymbolParams>) -> Result<CallToolResult, McpError> {
        let params = params.0;

        // Parse search mode from string
        let mode = match params.mode.as_deref() {
            Some("exact") => SearchMode::Exact,
            Some("prefix") => SearchMode::Prefix,
            Some("fuzzy") | None => SearchMode::Fuzzy,
            Some(other) => {
                return Err(McpError {
                    code: ErrorCode(-1),
                    message: format!("Invalid search mode: '{}'. Valid values: 'exact', 'fuzzy', 'prefix'", other).into(),
                    data: None,
                });
            }
        };

        // Parse symbol filter from string
        let filter = match params.filter.as_deref() {
            Some("types") => SymbolFilter::Types,
            Some("implementations") => SymbolFilter::Implementations,
            Some("functions") => SymbolFilter::Functions,
            Some("all") | None => SymbolFilter::All,
            Some(other) => {
                return Err(McpError {
                    code: ErrorCode(-1),
                    message: format!("Invalid filter: '{}'. Valid values: 'types', 'implementations', 'functions', 'all'", other).into(),
                    data: None,
                });
            }
        };

        // Build search options from parameters
        let options = SearchOptions {
            mode,
            include_library: params.include_library.unwrap_or(false),
            filter,
        };

        // Perform the search (lock the analyzer)
        let analyzer = self.analyzer.lock().unwrap();
        let results = analyzer.find_symbol(&params.name, &options)
            .map_err(|e| McpError {
                code: ErrorCode(-1),
                message: format!("Search failed: {}", e).into(),
                data: None,
            })?;

        // Format results as JSON
        let results_json: Vec<_> = results.iter().map(|sym| {
            json!({
                "name": sym.name,
                "kind": format!("{:?}", sym.kind),
                "file_path": sym.file_path,
                "start_line": sym.start_line,
                "end_line": sym.end_line,
                "documentation": sym.documentation,
            })
        }).collect();

        let summary = format!(
            "Found {} symbol(s) matching '{}' (mode: {:?}, library: {}, filter: {:?})",
            results.len(),
            params.name,
            mode,
            options.include_library,
            options.filter
        );

        Ok(CallToolResult::success(vec![
            Content::text(summary),
            Content::text(serde_json::to_string_pretty(&results_json).unwrap()),
        ]))
    }

    /// List all symbols defined in a specific file
    #[tool(description = "Enumerate all Rust symbols defined in a specific file")]
    async fn enumerate_file(&self, params: Parameters<EnumerateFileParams>) -> Result<CallToolResult, McpError> {
        let params = params.0;

        // Enumerate symbols in the file
        let analyzer = self.analyzer.lock().unwrap();
        let results = analyzer.enumerate_file(&params.file_path)
            .map_err(|e| McpError {
                code: ErrorCode(-1),
                message: format!("Failed to enumerate file: {}", e).into(),
                data: None,
            })?;

        // Format results as JSON with only requested fields
        let results_json: Vec<_> = results.iter().map(|sym| {
            json!({
                "name": sym.name,
                "kind": format!("{:?}", sym.kind),
                "start_line": sym.start_line,
                "end_line": sym.end_line,
            })
        }).collect();

        let summary = format!(
            "Found {} symbol(s) in '{}'",
            results.len(),
            params.file_path
        );

        Ok(CallToolResult::success(vec![
            Content::text(summary),
            Content::text(serde_json::to_string_pretty(&results_json).unwrap()),
        ]))
    }
}

#[tool_handler]
impl ServerHandler for CratographerServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation {
                name: "cratographer".to_string(),
                version: "0.1.0".to_string(),
                icons: None,
                title: None,
                website_url: None,
            },
            instructions: Some(
                "Cratographer: An MCP tool to help coding agents search symbols within Rust projects. \
                Use find_symbol to locate symbol definitions within the project and enumerate_file \
                to list all symbols in a file."
                    .to_string(),
            ),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create the server instance and start serving
    // This will fail if the project cannot be loaded
    let server = CratographerServer::new()?;
    let service = server.serve(stdio()).await?;

    // Wait for shutdown
    service.waiting().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_find_symbol_returns_ok() {
        let server = CratographerServer::new().expect("Failed to create server");

        // Create parameters to search for "Analyzer"
        let params = Parameters(FindSymbolParams {
            name: "Analyzer".to_string(),
            mode: Some("fuzzy".to_string()),
            include_library: Some(false),
            filter: Some("all".to_string()),
        });

        let result = server.find_symbol(params).await;

        assert!(result.is_ok(), "find_symbol should return Ok: {:?}", result.err());
        let tool_result = result.unwrap();

        // Check that we got content back
        assert!(!tool_result.content.is_empty(), "Result should contain content");

        // Verify it's a success result (not an error)
        assert!(!tool_result.is_error.unwrap_or(false), "Result should not be an error");

        // Just print the debug output
        println!("Result: {:?}", tool_result.content);
    }

    #[tokio::test]
    async fn test_find_symbol_exact_search() {
        let server = CratographerServer::new().expect("Failed to create server");

        // Exact search for "Analyzer"
        let params = Parameters(FindSymbolParams {
            name: "Analyzer".to_string(),
            mode: Some("exact".to_string()),
            include_library: Some(false),
            filter: Some("all".to_string()),
        });

        let result = server.find_symbol(params).await;
        assert!(result.is_ok(), "find_symbol should return Ok");

        let tool_result = result.unwrap();
        let content_str = format!("{:?}", tool_result.content);
        println!("Exact search result: {}", content_str);

        // Verify the search mode is Exact in the output
        assert!(content_str.contains("mode: Exact"), "Should use Exact search mode");
    }

    #[tokio::test]
    async fn test_find_symbol_with_library() {
        let server = CratographerServer::new().expect("Failed to create server");

        // Search for HashMap with library symbols
        let params = Parameters(FindSymbolParams {
            name: "HashMap".to_string(),
            mode: Some("exact".to_string()),
            include_library: Some(true),
            filter: Some("all".to_string()),
        });

        let result = server.find_symbol(params).await;
        assert!(result.is_ok(), "find_symbol should return Ok");

        // Should find HashMap from the standard library
        let content_str = format!("{:?}", result.unwrap().content);
        assert!(content_str.contains("HashMap"), "Should find HashMap");
    }

    #[tokio::test]
    async fn test_enumerate_file_returns_ok() {
        let server = CratographerServer::new().expect("Failed to create server");

        // Get the absolute path to analyzer.rs
        let analyzer_path = std::env::current_dir()
            .expect("Failed to get current directory")
            .join("src/analyzer.rs")
            .canonicalize()
            .expect("Failed to canonicalize analyzer.rs path");

        // Create parameters for enumerate_file
        let params = Parameters(EnumerateFileParams {
            file_path: analyzer_path.to_str().unwrap().to_string(),
        });

        let result = server.enumerate_file(params).await;

        assert!(result.is_ok(), "enumerate_file should return Ok: {:?}", result.err());
        let tool_result = result.unwrap();

        // Check that we got content back
        assert!(!tool_result.content.is_empty(), "Result should contain content");

        // Verify it's a success result (not an error)
        assert!(!tool_result.is_error.unwrap_or(false), "Result should not be an error");

        // Print the result for debugging
        println!("Result: {:?}", tool_result.content);
    }

    #[test]
    fn test_server_info() {
        let server = CratographerServer::new().expect("Failed to create server");
        let info = server.get_info();

        // Verify server name and version
        assert_eq!(info.server_info.name, "cratographer");
        assert_eq!(info.server_info.version, "0.1.0");

        // Verify protocol version
        assert_eq!(info.protocol_version, ProtocolVersion::V_2024_11_05);

        // Verify capabilities - should have tools enabled
        assert!(
            info.capabilities.tools.is_some(),
            "Server should have tools capability"
        );

        // Verify instructions are present
        assert!(
            info.instructions.is_some(),
            "Server should have instructions"
        );
        let instructions = info.instructions.unwrap();
        assert!(
            instructions.to_lowercase().contains("cratographer"),
            "Instructions should mention Cratographer"
        );
        assert!(
            instructions.contains("find_symbol"),
            "Instructions should mention find_symbol"
        );
        assert!(
            instructions.contains("enumerate_file"),
            "Instructions should mention enumerate_file"
        );
    }

    #[test]
    fn test_server_creation() {
        let _server = CratographerServer::new().expect("Failed to create server");
        // Just verify we can create the server without panicking
        // If we get here, the server was created successfully
    }
}
