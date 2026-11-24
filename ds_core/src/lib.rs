//! DeepSeek 核心模块 —— OpenAI API 到 DeepSeek 的适配层
//!
//! 对外暴露最小接口：DsCore, CoreError, ChatRequest, DsCoreConfig, AccountConfig

mod accounts;
mod chat;
mod config;

pub use accounts::{AccountFailure, AccountStatus, AccountUnavailable, FailureKind, PoolError};
pub use accounts::{
    ChatSessionInfo, ClientIdentity, DsClient, EmulationProfile, FetchSessionsData, HifConfig,
    LoginPayload,
};
pub use chat::{ChatRequest, ChatResponse, DeltaPrompt, FilePayload, StreamEvent};
pub use config::{AccountConfig, DsCoreConfig};

use accounts::Accounts;
use chat::Chat;
use std::sync::Arc;

/// 内核层错误类型
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// 服务过载：所有账号都在忙或不健康
    #[error("no available account")]
    Overloaded,

    /// PoW 计算失败
    #[error("proof of work failed: {0}")]
    ProofOfWorkFailed(#[from] accounts::PowError),

    /// 提供商错误：网络、业务错误、Token 失效等
    #[error("provider: {0}")]
    ProviderError(String),

    /// 流处理错误：连接中断等
    #[error("stream error: {0}")]
    Stream(String),

    /// 请求指定的账号（`ChatRequest::account`）当前无法承接请求
    #[error("account {id}: {reason}")]
    Account {
        id: String,
        reason: AccountUnavailable,
    },
}

impl From<accounts::ClientError> for CoreError {
    fn from(e: accounts::ClientError) -> Self {
        CoreError::ProviderError(e.to_string())
    }
}

pub struct DsCore {
    accounts: Arc<Accounts>,
    chat: Chat,
}

impl DsCore {
    pub async fn new(
        config: &DsCoreConfig,
        account_creds: Vec<AccountConfig>,
    ) -> Result<Self, CoreError> {
        let accounts = Accounts::new(config, account_creds).await?;
        let chat = Chat::new(Arc::clone(&accounts), config);

        Ok(Self { accounts, chat })
    }

    /// 发起对话请求，返回 SSE 字节流 + 账号标识
    ///
    /// 流结束或丢弃时自动释放账号
    pub async fn v0_chat(
        &self,
        req: ChatRequest,
        request_id: &str,
    ) -> Result<ChatResponse, CoreError> {
        self.chat.v0_chat(req, request_id).await
    }

    #[must_use]
    pub fn account_statuses(&self) -> Vec<AccountStatus> {
        self.accounts.account_statuses()
    }

    /// 获取详细账号状态（含滑动窗口统计、请求间隔等）
    #[must_use]
    pub fn account_statuses_detailed(&self) -> Vec<AccountStatus> {
        self.accounts.account_statuses_detailed()
    }

    /// 拉取账号的会话列表（分页；`updated_at` 为游标，None = 第一页）
    pub async fn fetch_sessions(
        &self,
        updated_at: Option<f64>,
    ) -> Result<accounts::FetchSessionsData, CoreError> {
        self.accounts.fetch_sessions(updated_at).await
    }

    /// 让账号池与期望列表一致：新增 / 凭据变化的账号登录，未变的保持原状，
    /// `remove_missing` 时移除列表之外的账号。返回期望列表中各账号的状态。
    pub async fn sync_accounts(
        &self,
        desired: Vec<AccountConfig>,
        remove_missing: bool,
    ) -> Result<Vec<AccountStatus>, PoolError> {
        self.accounts.sync_accounts(desired, remove_missing).await
    }

    /// 移除账号（正在进行的请求会正常跑完）
    pub fn remove_account(&self, id: &str) -> Result<String, PoolError> {
        self.accounts.remove_account(id)
    }

    /// 重新登录指定账号
    pub async fn relogin(&self, id: &str) -> Result<AccountStatus, PoolError> {
        self.accounts.relogin(id).await
    }

    /// 优雅关闭：清理所有残留 session（活动中的 + 复用缓存的）
    pub async fn shutdown(&self) {
        self.chat.shutdown().await;
        let reaped = self.accounts.reap_all_sessions().await;
        if reaped > 0 {
            log::info!(target: "ds_core::accounts", "shutdown: 回收 {reaped} 个复用会话");
        }
    }

    pub async fn reload_config(&self, config: &DsCoreConfig) -> Result<(), CoreError> {
        self.accounts.reload_config(config).await
    }
}
