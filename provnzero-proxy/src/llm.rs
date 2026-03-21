use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use zeroize::Zeroize;

#[async_trait]
pub trait LlmClient: Send + Sync {
    async fn complete(
        &self,
        prompt: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>>;
    fn provider_name(&self) -> &str;
}

pub struct OpenAIClient {
    client: Client,
    api_key: String,
    model: String,
    base_url: String,
}

#[derive(Serialize, Zeroize)]
#[zeroize(drop)]
struct OpenAIRequest {
    model: String,
    prompt: String,
    max_tokens: u32,
    temperature: f32,
}

#[derive(Deserialize, Debug, Zeroize)]
#[zeroize(drop)]
struct OpenAIResponse {
    choices: Vec<Choice>,
}

#[derive(Deserialize, Debug, Zeroize)]
#[zeroize(drop)]
struct Choice {
    text: String,
}

impl OpenAIClient {
    pub fn new(api_key: String, model: Option<String>, base_url: Option<String>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            api_key,
            model: model.unwrap_or_else(|| "gpt-3.5-turbo".to_string()),
            base_url: base_url.unwrap_or_else(|| "https://api.openai.com/v1".to_string()),
        }
    }
}

#[async_trait]
impl LlmClient for OpenAIClient {
    async fn complete(
        &self,
        prompt: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/completions", self.base_url);

        let mut request = OpenAIRequest {
            model: self.model.clone(),
            prompt: prompt.to_string(),
            max_tokens: 500,
            temperature: 0.7,
        };

        let response = self
            .client
            .post(url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?;

        // Zeroize request after sending
        request.zeroize();

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("OpenAI API error: {} - {}", status, body).into());
        }

        let mut result: OpenAIResponse = response.json().await?;
        let text = result
            .choices
            .first()
            .map(|c| c.text.clone())
            .unwrap_or_default();

        // Zeroize response structure
        result.zeroize();

        Ok(text)
    }

    fn provider_name(&self) -> &str {
        "openai"
    }
}

pub struct AnthropicClient {
    client: Client,
    api_key: String,
    model: String,
}

#[derive(Serialize, Zeroize)]
#[zeroize(drop)]
struct AnthropicRequest {
    model: String,
    prompt: String,
    max_tokens_to_sample: u32,
    temperature: f32,
}

#[derive(Deserialize, Debug, Zeroize)]
#[zeroize(drop)]
struct AnthropicResponse {
    completion: String,
}

impl AnthropicClient {
    pub fn new(api_key: String, model: Option<String>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            api_key,
            model: model.unwrap_or_else(|| "claude-3-haiku-20240307".to_string()),
        }
    }
}

#[async_trait]
impl LlmClient for AnthropicClient {
    async fn complete(
        &self,
        prompt: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let mut formatted_prompt = format!("\n\nHuman: {}\n\nAssistant:", prompt);
        let url = "https://api.anthropic.com/v1/complete";

        let mut request = AnthropicRequest {
            model: self.model.clone(),
            prompt: formatted_prompt.clone(),
            max_tokens_to_sample: 500,
            temperature: 0.7,
        };

        let response = self
            .client
            .post(url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?;

        // Zeroize intermediate strings and request
        formatted_prompt.zeroize();
        request.zeroize();

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("Anthropic API error: {} - {}", status, body).into());
        }

        let mut result: AnthropicResponse = response.json().await?;
        let text = result.completion.clone();

        // Zeroize response structure
        result.zeroize();

        Ok(text)
    }

    fn provider_name(&self) -> &str {
        "anthropic"
    }
}

pub struct DeepSeekClient {
    client: Client,
    api_key: String,
    model: String,
}

#[derive(Serialize, Zeroize)]
#[zeroize(drop)]
struct DeepSeekRequest {
    model: String,
    prompt: String,
    max_tokens: u32,
    temperature: f32,
}

#[derive(Deserialize, Debug, Zeroize)]
#[zeroize(drop)]
struct DeepSeekResponse {
    choices: Vec<Choice>,
}

impl DeepSeekClient {
    pub fn new(api_key: String, model: Option<String>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            api_key,
            model: model.unwrap_or_else(|| "deepseek-chat".to_string()),
        }
    }
}

#[async_trait]
impl LlmClient for DeepSeekClient {
    async fn complete(
        &self,
        prompt: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let url = "https://api.deepseek.com/v1/completions";

        let mut request = DeepSeekRequest {
            model: self.model.clone(),
            prompt: prompt.to_string(),
            max_tokens: 500,
            temperature: 0.7,
        };

        let response = self
            .client
            .post(url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?;

        // Zeroize request
        request.zeroize();

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("DeepSeek API error: {} - {}", status, body).into());
        }

        let mut result: DeepSeekResponse = response.json().await?;
        let text = result
            .choices
            .first()
            .map(|c| c.text.clone())
            .unwrap_or_default();

        // Zeroize response structure
        result.zeroize();

        Ok(text)
    }

    fn provider_name(&self) -> &str {
        "deepseek"
    }
}

pub struct LlmClientRegistry {
    pub clients: RwLock<Vec<Arc<dyn LlmClient>>>,
    pub default_provider: RwLock<Option<String>>,
}

impl LlmClientRegistry {
    pub fn new() -> Self {
        Self {
            clients: RwLock::new(Vec::new()),
            default_provider: RwLock::new(None),
        }
    }

    pub async fn add_client(&self, client: Arc<dyn LlmClient>) {
        let mut clients = self.clients.write().await;
        clients.push(client);
    }

    pub async fn set_default(&self, provider: String) {
        let mut default = self.default_provider.write().await;
        *default = Some(provider);
    }

    pub async fn get_client(&self, provider: Option<&str>) -> Option<Arc<dyn LlmClient>> {
        let clients = self.clients.read().await;

        if let Some(p) = provider {
            for client in clients.iter() {
                if client.provider_name() == p {
                    return Some(Arc::clone(client));
                }
            }
        }

        let default = self.default_provider.read().await;
        if let Some(ref p) = *default {
            for client in clients.iter() {
                if client.provider_name() == p {
                    return Some(Arc::clone(client));
                }
            }
        }

        clients.first().map(Arc::clone)
    }

    pub async fn has_clients(&self) -> bool {
        let clients = self.clients.read().await;
        !clients.is_empty()
    }
}

impl Default for LlmClientRegistry {
    fn default() -> Self {
        Self::new()
    }
}
