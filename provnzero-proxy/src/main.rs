use axum::{
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};
use zeroize::Zeroize;

mod crypto;
mod llm;
mod receipt;
mod secure_buffer;

use crypto::generate_keypair;
use llm::{AnthropicClient, DeepSeekClient, LlmClientRegistry, OpenAIClient};
use receipt::VexReceipt;
use secure_buffer::SecureBuffer;

#[derive(Clone)]
struct AppState {
    attest_key: ed25519_dalek::SigningKey,
    ephemeral_keys: Arc<RwLock<std::collections::HashMap<String, EphemeralKeyState>>>,
    llm_registry: Arc<LlmClientRegistry>,
}

#[derive(Clone)]
struct EphemeralKeyState {
    secret_bytes: SecureBuffer,
    created_at: std::time::Instant,
}

#[derive(Serialize, Deserialize)]
struct EphemeralKeyResponse {
    pubkey: String,
    key_id: String,
}

#[derive(Deserialize)]
struct EncryptedRequest {
    key_id: String,
    encapsulated_key: String,
    ciphertext: String,
    provider: Option<String>,
}

#[derive(Serialize)]
struct EncryptedResponse {
    encapsulated_key: String,
    ciphertext: String,
    done: bool,
    receipt: Option<String>,
    provider: Option<String>,
}

fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    STANDARD.decode(input).map_err(|e| e.to_string())
}

fn base64_encode(input: &[u8]) -> String {
    STANDARD.encode(input)
}

async fn generate_ephemeral_keypair() -> (String, EphemeralKeyState, Vec<u8>) {
    let (secret_bytes, pubkey_bytes) = generate_keypair();

    let key_id = base64_encode(&rand::random::<[u8; 16]>());

    let key_state = EphemeralKeyState {
        secret_bytes: SecureBuffer::from_vec(secret_bytes),
        created_at: std::time::Instant::now(),
    };

    (key_id, key_state, pubkey_bytes)
}

// HPKE handles nonces internal to AEAD context

fn sign_receipt(attest_key: &ed25519_dalek::SigningKey, receipt: &VexReceipt) -> String {
    use ed25519_dalek::Signer;

    let message = format!(
        "{}:{}:{}:{}",
        receipt.request_id,
        receipt.processed_at,
        receipt.provider.as_deref().unwrap_or("demo"),
        receipt.memory_zeroized
    );

    let signature = attest_key.sign(message.as_bytes());
    base64_encode(signature.to_bytes().as_ref())
}

fn generate_vex_receipt(
    request_id: &str,
    provider: Option<&str>,
    attest_key: &ed25519_dalek::SigningKey,
) -> VexReceipt {
    let mut receipt = VexReceipt::new(request_id, provider.map(String::from));
    let signature = sign_receipt(attest_key, &receipt);
    receipt.signature = Some(signature);
    receipt
}

async fn handle_health() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        r#"{"status":"healthy","service":"provnzero-zdr"}"#,
    )
}

async fn handle_init(
    State(state): State<AppState>,
) -> Result<Json<EphemeralKeyResponse>, StatusCode> {
    let (key_id, key_state, pubkey_bytes) = generate_ephemeral_keypair().await;

    {
        let mut keys = state.ephemeral_keys.write().await;
        keys.insert(key_id.clone(), key_state);
    }

    Ok(Json(EphemeralKeyResponse {
        pubkey: base64_encode(&pubkey_bytes),
        key_id,
    }))
}

async fn handle_request(
    State(state): State<AppState>,
    Json(req): Json<EncryptedRequest>,
) -> Result<Json<EncryptedResponse>, StatusCode> {
    let key_state = {
        let keys = state.ephemeral_keys.read().await;
        keys.get(&req.key_id).cloned()
    };

    let key_state = key_state.ok_or(StatusCode::NOT_FOUND)?;

    // Decode inputs
    let encapsulated_key =
        base64_decode(&req.encapsulated_key).map_err(|_| StatusCode::BAD_REQUEST)?;
    let ciphertext = base64_decode(&req.ciphertext).map_err(|_| StatusCode::BAD_REQUEST)?;

    if encapsulated_key.len() < 32 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let server_privkey = key_state.secret_bytes.as_slice();

    // Decrypt prompt using standard HPKE Open
    let mut payload =
        crypto::hpke_open(&encapsulated_key, server_privkey, &ciphertext).map_err(|e| {
            tracing::error!("HPKE Decrypt error: {:?}", e);
            StatusCode::UNAUTHORIZED
        })?;

    let mut prompt = String::from_utf8_lossy(&payload).to_string();
    payload.zeroize();

    // Get LLM client
    let provider = req.provider.clone();
    let client = state.llm_registry.get_client(provider.as_deref()).await;

    let llm_response = if let Some(client) = client {
        match client.complete(&prompt).await {
            Ok(response) => response,
            Err(e) => {
                tracing::error!("LLM API error: {}", e);
                format!("Error: {}", e)
            }
        }
    } else {
        format!("Echo: {}", prompt)
    };

    // ZEROIZE the prompt immediately after LLM call
    prompt.zeroize();

    // Re-Seal response using a new ephemeral context back to client's X25519 public key
    // Re-use the encapsulated_key sent by client which *is* their ephemeral public key
    let (resp_encapped_key, response_ciphertext) =
        crypto::hpke_seal(&encapsulated_key[..32], llm_response.as_bytes()).map_err(|e| {
            tracing::error!("HPKE Encrypt error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Generate signed VEX receipt
    let receipt = generate_vex_receipt(&req.key_id, req.provider.as_deref(), &state.attest_key);
    println!("{}", receipt);

    tracing::info!("✅ Request {} processed - Memory Zeroized!", req.key_id);

    Ok(Json(EncryptedResponse {
        encapsulated_key: base64_encode(&resp_encapped_key),
        ciphertext: base64_encode(&response_ciphertext),
        done: true,
        receipt: Some(receipt.to_string()),
        provider,
    }))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let llm_registry = Arc::new(LlmClientRegistry::new());

    // Register OpenAI client if API key provided
    if let Ok(api_key) = std::env::var("OPENAI_API_KEY") {
        let model = std::env::var("OPENAI_MODEL").ok();
        let base_url = std::env::var("OPENAI_BASE_URL").ok();
        let client = Arc::new(OpenAIClient::new(api_key, model, base_url));
        llm_registry.add_client(client.clone()).await;
        llm_registry.set_default("openai".to_string()).await;
        tracing::info!("Registered OpenAI client");
    }

    // Register Anthropic client if API key provided
    if let Ok(api_key) = std::env::var("ANTHROPIC_API_KEY") {
        let model = std::env::var("ANTHROPIC_MODEL").ok();
        let client = Arc::new(AnthropicClient::new(api_key, model));
        llm_registry.add_client(client.clone()).await;
        tracing::info!("Registered Anthropic client");
    }

    // Register DeepSeek client if API key provided
    if let Ok(api_key) = std::env::var("DEEPSEEK_API_KEY") {
        let model = std::env::var("DEEPSEEK_MODEL").ok();
        let client = Arc::new(DeepSeekClient::new(api_key, model));
        llm_registry.add_client(client.clone()).await;
        tracing::info!("Registered DeepSeek client");
    }

    let has_clients = llm_registry.has_clients().await;

    if !has_clients {
        tracing::info!("No LLM API keys detected - running in demo mode (echo)");
    }

    let attest_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());

    let state = AppState {
        attest_key,
        ephemeral_keys: Arc::new(RwLock::new(std::collections::HashMap::new())),
        llm_registry,
    };

    // Background task: Prune expired ephemeral keys every 5 minutes
    let keys_clone = state.ephemeral_keys.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            let mut keys = keys_clone.write().await;
            let now = std::time::Instant::now();
            // Remove keys older than 30 minutes
            keys.retain(|_, v| now.duration_since(v.created_at).as_secs() < 1800);
            tracing::info!(
                "Pruned expired ephemeral keys. Active count: {}",
                keys.len()
            );
        }
    });

    let global_governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(500)
            .burst_size(1000)
            .finish()
            .unwrap(),
    );

    let init_governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(5)
            .burst_size(20)
            .finish()
            .unwrap(),
    );

    let app = Router::new()
        .route("/health", get(handle_health))
        .route(
            "/v1/init",
            post(handle_init).layer(GovernorLayer {
                config: init_governor_conf,
            }),
        )
        .route("/v1/completions", post(handle_request))
        .with_state(state)
        .layer(GovernorLayer {
            config: global_governor_conf,
        });

    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3001);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    tracing::info!(
        "ProvnZero proxy listening on {}",
        listener.local_addr().unwrap()
    );

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .unwrap();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Shutdown signal received (Ctrl+C). Starting graceful shutdown...");
        },
        _ = terminate => {
            tracing::info!("Shutdown signal received (Terminate). Starting graceful shutdown...");
        },
    }
}
