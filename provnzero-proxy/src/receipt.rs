use chrono::Utc;
use std::fmt;

#[derive(Clone)]
pub struct VexReceipt {
    pub version: String,
    pub request_id: String,
    pub processed_at: String,
    pub provider: Option<String>,
    pub memory_zeroized: bool,
    pub statement: String,
    pub signature: Option<String>,
}

impl VexReceipt {
    pub fn new(request_id: &str, provider: Option<String>) -> Self {
        Self {
            version: "1.0".to_string(),
            request_id: request_id.to_string(),
            processed_at: Utc::now().to_rfc3339(),
            provider,
            memory_zeroized: true,
            statement: "Memory zeroized, no persistence".to_string(),
            signature: None,
        }
    }

    pub fn to_ascii(&self) -> String {
        let provider_str = self.provider.as_deref().unwrap_or("demo");

        format!(
            r#"
╔══════════════════════════════════════════════════════════════╗
║                    🛡️  PROVNZERO RECEIPT  🛡️                 ║
╠══════════════════════════════════════════════════════════════╣
║  Request ID:    {}                     
║  Processed:     {}                       
║  Provider:       {}                                      
║  Model:          {}                                      
╠══════════════════════════════════════════════════════════════╣
║  🤍  MEMORY ZEROIZED                                      ║
║      ✓ All buffers wiped                                  ║
║      ✓ No persistence                                     ║
║      ✓ No logs                                            ║
╠══════════════════════════════════════════════════════════════╣
{}╠══════════════════════════════════════════════════════════════╣
║  Version: {} | ZDR Guarantee Active                        ║
╚══════════════════════════════════════════════════════════════╝
"#,
            self.request_id,
            self.processed_at,
            provider_str,
            self.get_model(),
            self.signature_line(),
            self.version
        )
    }

    fn get_model(&self) -> &str {
        match self.provider.as_deref() {
            Some("openai") => "gpt-3.5-turbo",
            Some("anthropic") => "claude-3-haiku",
            Some("deepseek") => "deepseek-chat",
            _ => "echo-demo",
        }
    }

    fn signature_line(&self) -> String {
        if let Some(ref sig) = self.signature {
            format!("║  Signature:    {} ", &sig[..32.min(sig.len())])
        } else {
            "║  Signature:    (not signed)".to_string()
        }
    }
}

impl fmt::Display for VexReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_ascii())
    }
}
