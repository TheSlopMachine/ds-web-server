//! 账号池管理 —— 多账号负载均衡
//!
//! 1 account = 1 session = 1 concurrency。多并发需横向扩展账号数。

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, AtomicU8, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use dashmap::DashMap;
use futures::TryStreamExt;
use futures::future::join_all;
use log::{debug, error, info, warn};
use tokio::sync::{RwLock, Semaphore};

use super::client::{ClientError, CompletionPayload, DsClient, LoginPayload};
use super::pow::{PowError, PowSolver};
use crate::config::AccountConfig;

/// 账号状态枚举
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountState {
    Idle = 0,
    Busy = 1,
    Error = 2,
    Invalid = 3,
}

impl AccountState {
    const fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Idle,
            1 => Self::Busy,
            2 => Self::Error,
            _ => Self::Invalid,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Busy => "busy",
            Self::Error => "error",
            Self::Invalid => "invalid",
        }
    }
}

/// 登录 / 恢复失败的分类
///
/// 调用方（管理 API、按账号路由的请求）据此决定是否值得重试、该提示用户做什么。
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    /// 账号或密码错误（biz_code 2）
    InvalidCredentials,
    /// 账号被禁言（biz_code 5 或登录响应 `is_muted`），到 `mute_until` 后自动重试
    Muted,
    /// 账号被封禁（biz_code 10）
    Banned,
    /// 设备指纹被拒（biz_code 11，`RISK_DEVICE_DETECTED`）
    DeviceRejected,
    /// 其它业务错误
    Rejected,
    /// WAF 质询（出口 IP 或指纹被拦截）
    Blocked,
    /// 启动健康检查失败
    HealthCheck,
    /// 账号配置不合法（email 与 mobile 同时为空）
    InvalidConfig,
    /// 网络 / 上游临时错误，可重试
    Unavailable,
}

impl FailureKind {
    /// 终止性失败：重试不会改变结果（禁言等到 `mute_until` 由恢复任务处理）
    ///
    /// 文档明确「禁言后继续重试不会加速解禁，反而可能延长」，所以这些失败直接置 Invalid。
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Unavailable)
    }
}

/// 账号最近一次登录失败的原因
#[derive(Clone, Debug, serde::Serialize)]
pub struct AccountFailure {
    pub kind: FailureKind,
    /// 上游或本地给出的原始说明
    pub message: String,
    /// 上游业务码（仅业务错误）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub biz_code: Option<i64>,
    /// 禁言解除时间（Unix 秒，上游原样给出的小数，仅 `muted`）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mute_until: Option<f64>,
    /// 失败时间（Unix 秒）
    pub at: i64,
}

impl AccountFailure {
    fn from_error(e: &PoolError) -> Self {
        let (kind, biz_code, mute_until) = match e {
            PoolError::Client(ClientError::Business { code, .. }) => {
                let kind = match code {
                    2 => FailureKind::InvalidCredentials,
                    5 => FailureKind::Muted,
                    10 => FailureKind::Banned,
                    11 => FailureKind::DeviceRejected,
                    _ => FailureKind::Rejected,
                };
                (kind, Some(*code), None)
            }
            PoolError::Client(ClientError::Status { status: 202, .. }) => {
                (FailureKind::Blocked, None, None)
            }
            PoolError::Muted { mute_until } => (FailureKind::Muted, None, *mute_until),
            PoolError::HealthCheck(_) => (FailureKind::HealthCheck, None, None),
            PoolError::Validation(_) => (FailureKind::InvalidConfig, None, None),
            _ => (FailureKind::Unavailable, None, None),
        };
        Self {
            kind,
            message: e.to_string(),
            biz_code,
            mute_until,
            at: now_secs(),
        }
    }

    /// 距禁言解除还剩多久（已到期为零；非禁言或时间未知为 None）
    #[must_use]
    pub fn mute_remaining(&self) -> Option<Duration> {
        let until = SystemTime::UNIX_EPOCH
            .checked_add(Duration::try_from_secs_f64(self.mute_until?).ok()?)?;
        Some(
            until
                .duration_since(SystemTime::now())
                .unwrap_or(Duration::ZERO),
        )
    }

    /// 禁言已到期：恢复任务可以再试一次登录
    fn mute_expired(&self) -> bool {
        self.kind == FailureKind::Muted && self.mute_remaining().is_some_and(|d| d.is_zero())
    }
}

/// 指定账号（`ChatRequest::account`）当前无法承接请求的原因
#[derive(Clone, Debug)]
pub enum AccountUnavailable {
    /// 池中没有这个账号
    NotFound,
    /// 账号一直忙（1 账号 = 1 并发），等待超时
    Busy,
    /// 账号在 Error 状态，恢复任务会自动重新登录
    Recovering,
    /// 本小时配额用尽
    QuotaExhausted { retry_after_secs: u64 },
    /// 账号已失效（登录失败、被禁言 / 封禁等）
    Failed(AccountFailure),
}

impl AccountUnavailable {
    /// 稳定的机器可读错误码（HTTP 错误信封的 `code`）
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NotFound => "account_not_found",
            Self::Busy => "account_busy",
            Self::Recovering => "account_recovering",
            Self::QuotaExhausted { .. } => "account_quota_exhausted",
            Self::Failed(failure) => match failure.kind {
                FailureKind::InvalidCredentials => "account_invalid_credentials",
                FailureKind::Muted => "account_muted",
                FailureKind::Banned => "account_banned",
                FailureKind::DeviceRejected => "account_device_rejected",
                FailureKind::Rejected => "account_rejected",
                FailureKind::Blocked => "account_blocked",
                FailureKind::HealthCheck => "account_health_check_failed",
                FailureKind::InvalidConfig => "account_invalid_config",
                FailureKind::Unavailable => "account_unavailable",
            },
        }
    }

    /// 建议的重试等待秒数；None = 重试不会改变结果
    #[must_use]
    pub fn retry_after_secs(&self) -> Option<u64> {
        const RECOVERY_SECS: u64 = 60;
        match self {
            Self::NotFound => None,
            Self::Busy => Some(5),
            Self::Recovering => Some(RECOVERY_SECS),
            Self::QuotaExhausted { retry_after_secs } => Some(*retry_after_secs),
            Self::Failed(failure) => match failure.kind {
                FailureKind::Muted => failure
                    .mute_remaining()
                    .map(|d| d.as_secs() + u64::from(d.subsec_nanos() > 0)),
                FailureKind::Blocked | FailureKind::Unavailable => Some(RECOVERY_SECS),
                _ => None,
            },
        }
    }
}

impl std::fmt::Display for AccountUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "account not found"),
            Self::Busy => write!(f, "account is busy"),
            Self::Recovering => write!(f, "account is recovering, re-login pending"),
            Self::QuotaExhausted { retry_after_secs } => write!(
                f,
                "account hourly request quota exhausted, retry in {retry_after_secs}s"
            ),
            Self::Failed(failure) => write!(f, "account unavailable: {}", failure.message),
        }
    }
}

/// 账号状态信息
#[derive(serde::Serialize)]
pub struct AccountStatus {
    /// 账号标识：email 优先，回退 mobile（管理 API 与 `X-DS-Account` 用它定位账号）
    pub id: String,
    pub email: String,
    pub mobile: String,
    pub state: String,
    /// 最后释放时间戳（ms），0 表示从未使用
    pub last_released_ms: i64,
    /// 窗口起点（Unix 秒）
    pub window_started_at: i64,
    /// 窗口内剩余秒数
    pub window_remaining_secs: i64,
    /// 总请求数（累计）
    pub total_requests: u64,
    /// 首次请求时间戳（ms）
    pub first_request_ms: i64,
    /// 最后请求时间戳（ms）
    pub last_request_ms: i64,
    /// 最近请求间隔（秒）
    pub recent_intervals: Vec<i64>,
    /// 连续登录失败次数
    pub error_count: u8,
    /// 当前配额窗口内已用请求数
    pub used_this_hour: u64,
    /// 本窗口是否已用尽配额（0 配额 = 不限制，恒为 false）
    pub quota_exhausted: bool,
    /// 最近一次登录失败的原因；登录成功后清空
    pub failure: Option<AccountFailure>,
}

impl AccountStatus {
    fn from_account(account: &Account, hourly_quota: u64) -> Self {
        let (total, window_used, first, last, intervals) = account.window.get_stats();
        // For sliding window, compute window start as earliest timestamp in current window
        let window_started = {
            let now = now_secs();
            let ts = account.window.timestamps.lock().unwrap();
            ts.front().copied().unwrap_or(now)
        };
        let window_remaining = (window_started + WINDOW_SECS - now_secs()).max(0);
        Self {
            id: account.display_id().to_string(),
            email: account.email.clone(),
            mobile: account.mobile.clone(),
            state: account.state().as_str().to_string(),
            last_released_ms: account.last_released.load(Ordering::Relaxed),
            window_started_at: window_started,
            window_remaining_secs: window_remaining,
            total_requests: total,
            first_request_ms: first * 1000,
            last_request_ms: last * 1000,
            recent_intervals: intervals,
            error_count: account.error_count.load(Ordering::Relaxed),
            used_this_hour: window_used,
            quota_exhausted: !account.within_quota(hourly_quota),
            failure: account.failure(),
        }
    }
}

pub struct Account {
    token: std::sync::RwLock<Arc<str>>,
    email: String,
    mobile: String,
    state: AtomicU8,
    /// 账号最近一次释放的时间戳（ms），用于冷却判断
    last_released: AtomicI64,
    /// 连续登录失败次数
    error_count: AtomicU8,
    /// 最近一次登录失败的原因（成功后清空）
    failure: Mutex<Option<AccountFailure>>,
    /// 原始凭据（用于重新登录）
    creds: AccountConfig,
    /// 滑动窗口限流器（用于每小时配额）
    window: SlidingWindowRateLimiter,
    /// 复用会话槽（`session_reuse = true` 时使用）
    ///
    /// 真实客户端一个会话长期复用、几乎不删；这里保存最近一次成功完成的会话，
    /// 空闲超过阈值由后台任务回收（见 `AccountPool::reap_sessions`）。
    session: Mutex<Option<CachedSession>>,
    /// 绑定该账号设备身份（X-Device-Id）的客户端视图
    ///
    /// 真实 Web 客户端「一个浏览器 profile = 一个数美 device_id + 一个
    /// X-Device-Id」，HIF 风控令牌也按设备下发；这里按账号派生，
    /// 避免多账号共用同一设备身份与同一令牌。
    client: DsClient,
}

/// 复用会话槽里的一条记录
struct CachedSession {
    id: String,
    last_used: Instant,
    /// 上游该会话当前已知的消息指纹链（`DeltaPrompt::chain` 的快照）
    ///
    /// 下一次请求只有在「自己的链以它开头」时才允许增量发送 —— 这保证
    /// 上游会话里的上下文与客户端发来的历史严格一致。
    chain: Vec<u64>,
    /// 该会话上一条响应的消息 id（作为下一轮的 `parent_message_id`）
    last_message_id: i64,
}

/// 连续登录失败上限，达到后标记为 Invalid
const MAX_ERROR_COUNT: u8 = 3;

/// 配额窗口长度：1 小时
const WINDOW_SECS: i64 = 3600;

fn now_secs() -> i64 {
    unix_timestamp_secs().unwrap_or(i64::MAX)
}

/// 当前 Unix 时间戳（毫秒），用于账号释放冷却判断
fn now_ms() -> i64 {
    unix_timestamp_millis().unwrap_or(i64::MAX)
}

/// Unix 秒级时间戳；系统时钟异常（早于 EPOCH / 溢出 i64）时返回 None
fn unix_timestamp_secs() -> Option<i64> {
    i64::try_from(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()?
            .as_secs(),
    )
    .ok()
}

/// Unix 毫秒级时间戳；系统时钟异常（早于 EPOCH / 溢出 i64）时返回 None
fn unix_timestamp_millis() -> Option<i64> {
    i64::try_from(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()?
            .as_millis(),
    )
    .ok()
}

/// 严格滑动窗口限流器
///
/// 保证：任意时刻，最近 `WINDOW_SECS` 秒内的请求数 ≤ 配额
/// 使用 VecDeque 存储请求时间戳（Unix 秒），自动清理过期项。
///
/// 设计为无锁读 + 细粒度锁写，适合高并发场景。
struct SlidingWindowRateLimiter {
    timestamps: Mutex<VecDeque<i64>>,
    /// 总请求数（累计，跨窗口）
    total_count: AtomicU64,
    /// 首次请求时间戳（Unix 秒）
    first_request_at: AtomicI64,
    /// 最后请求时间戳（Unix 秒）
    last_request_at: AtomicI64,
    /// 请求间隔记录（最近 10 个，Unix 秒差值）
    recent_intervals: Mutex<Vec<i64>>,
}

impl SlidingWindowRateLimiter {
    const fn new() -> Self {
        Self {
            timestamps: Mutex::new(VecDeque::new()),
            total_count: AtomicU64::new(0),
            first_request_at: AtomicI64::new(0),
            last_request_at: AtomicI64::new(0),
            recent_intervals: Mutex::new(Vec::new()),
        }
    }

    fn record_interval(&self, now: i64) {
        let last = self.last_request_at.swap(now, Ordering::Relaxed);
        if last > 0 {
            let interval = now - last;
            if let Ok(mut intervals) = self.recent_intervals.lock() {
                intervals.push(interval);
                if intervals.len() > 10 {
                    intervals.remove(0);
                }
            }
        }
        let first = self.first_request_at.load(Ordering::Relaxed);
        if first == 0 {
            self.first_request_at.store(now, Ordering::Relaxed);
        }
    }

    fn get_stats(&self) -> (u64, u64, i64, i64, Vec<i64>) {
        let total = self.total_count.load(Ordering::Relaxed);
        let window_used = self.used();
        let first = self.first_request_at.load(Ordering::Relaxed);
        let last = self.last_request_at.load(Ordering::Relaxed);
        let intervals = self
            .recent_intervals
            .lock()
            .map(|v| v.clone())
            .unwrap_or_default();
        (total, window_used, first, last, intervals)
    }

    /// 记一次请求并返回窗口内的累计值；自动清理过期时间戳
    fn record(&self) -> u64 {
        let now = now_secs();
        let mut ts = self.timestamps.lock().unwrap();
        let cutoff = now - WINDOW_SECS;

        // 清理过期时间戳
        while ts.front().is_some_and(|&t| t < cutoff) {
            ts.pop_front();
        }

        ts.push_back(now);
        let window_used = ts.len() as u64;

        drop(ts); // 释放锁

        self.total_count.fetch_add(1, Ordering::Relaxed);
        self.record_interval(now);
        window_used
    }

    /// 配额为 `limit` 时，还要等多少秒窗口里才会空出一个名额（未用尽为 0）
    fn retry_after_secs(&self, limit: u64) -> u64 {
        let now = now_secs();
        let ts = self.timestamps.lock().unwrap();
        let excess = (ts.len() as u64 + 1).saturating_sub(limit);
        let Some(index) = excess.checked_sub(1).and_then(|i| usize::try_from(i).ok()) else {
            return 0;
        };
        ts.get(index)
            .map_or(0, |t| u64::try_from(t + WINDOW_SECS - now).unwrap_or(0))
    }

    /// 当前窗口内已用请求数（不修改状态）
    fn used(&self) -> u64 {
        let now = now_secs();
        let mut ts = self.timestamps.lock().unwrap();
        let cutoff = now - WINDOW_SECS;

        while ts.front().is_some_and(|&t| t < cutoff) {
            ts.pop_front();
        }

        ts.len() as u64
    }
}

impl Account {
    /// 记下可复用的会话（流正常结束后调用）
    pub(crate) fn put_cached_session(
        &self,
        session_id: &str,
        chain: Vec<u64>,
        last_message_id: i64,
    ) {
        let mut slot = self.session.lock().unwrap_or_else(|e| e.into_inner());
        *slot = Some(CachedSession {
            id: session_id.to_string(),
            last_used: Instant::now(),
            chain,
            last_message_id,
        });
    }

    /// 取可用于**增量发送**的会话
    ///
    /// 命中条件：缓存会话的消息链是本请求链的**严格前缀**，且只差 1~2 条消息
    /// （官方客户端的形态：`[…已有历史] + 自己的上一条回复 + 新的用户消息`）。
    /// 命中时顺带刷新 `last_used`，避免刚用过的会话被回收任务删掉。
    pub(crate) fn cached_session_for(&self, chain: &[u64]) -> Option<(String, i64)> {
        let mut slot = self.session.lock().unwrap_or_else(|e| e.into_inner());
        let cached = slot.as_mut()?;
        let known = cached.chain.len();
        let extra = chain.len().checked_sub(known)?;
        if !(1..=2).contains(&extra) || chain[..known] != cached.chain[..] {
            return None;
        }
        cached.last_used = Instant::now();
        let hit = (cached.id.clone(), cached.last_message_id);
        drop(slot);
        Some(hit)
    }

    /// 清掉缓存的会话（仅在 ID 匹配时，避免误删新会话）
    pub(crate) fn clear_cached_session(&self, session_id: &str) {
        let mut slot = self.session.lock().unwrap_or_else(|e| e.into_inner());
        if slot.as_ref().is_some_and(|c| c.id == session_id) {
            *slot = None;
        }
    }

    /// 取出需要回收的会话：`max_idle = None` 表示无条件回收（进程退出时）
    fn take_reapable_session(&self, max_idle: Option<Duration>) -> Option<String> {
        let mut slot = self.session.lock().unwrap_or_else(|e| e.into_inner());
        let due = match (slot.as_ref(), max_idle) {
            (Some(c), Some(idle)) => c.last_used.elapsed() >= idle,
            (Some(_), None) => true,
            (None, _) => false,
        };
        if due { slot.take().map(|c| c.id) } else { None }
    }

    pub fn token(&self) -> Arc<str> {
        self.token.read().unwrap().clone()
    }

    pub fn display_id(&self) -> &str {
        if self.email.is_empty() {
            &self.mobile
        } else {
            &self.email
        }
    }

    pub fn state(&self) -> AccountState {
        AccountState::from_u8(self.state.load(Ordering::Relaxed))
    }

    pub fn is_busy(&self) -> bool {
        self.state() == AccountState::Busy
    }

    pub fn is_available(&self) -> bool {
        self.state() == AccountState::Idle
    }

    /// 该账号在本配额窗口内是否还能继续使用
    ///
    /// `limit == 0` 表示不限制（保持既有行为）。
    fn within_quota(&self, limit: u64) -> bool {
        limit == 0 || self.window.used() < limit
    }

    /// 记一次请求用量；达到配额时打一次告警
    fn record_request(&self, limit: u64) {
        let used = self.window.record();
        if limit > 0 && used == limit {
            warn!(
                target: "ds_core::accounts",
                "Account {} reached the hourly request budget ({}); it will be skipped until the window rolls over. \
                 Upstream mutes accounts after a few hundred requests per hour — spread load across more accounts.",
                self.display_id(), limit
            );
        }
    }

    /// 创建尚未登录的账号（Invalid、无令牌）；随后由 `record_login` 写入登录结果
    ///
    /// 设备身份按账号派生（空 device_id 时回退到全局配置的 X-Device-Id）。
    fn new(creds: AccountConfig, client: &DsClient) -> Self {
        let scoped = client.scoped_to(&account_x_device_id(&creds, client));
        Self {
            token: std::sync::RwLock::new(String::new().into()),
            email: creds.email.clone(),
            mobile: creds.mobile.clone(),
            state: AtomicU8::new(AccountState::Invalid as u8),
            last_released: AtomicI64::new(0),
            error_count: AtomicU8::new(0),
            failure: Mutex::new(None),
            creds,
            window: SlidingWindowRateLimiter::new(),
            session: Mutex::new(None),
            client: scoped,
        }
    }

    /// 最近一次登录失败的原因
    pub fn failure(&self) -> Option<AccountFailure> {
        self.failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// 写入一次登录结果
    ///
    /// 成功 → Idle 并清空失败记录；失败 → 记录原因，终止性失败或连续
    /// `MAX_ERROR_COUNT` 次失败置 Invalid，否则置 Error 交给恢复任务重试。
    fn record_login(&self, result: Result<String, PoolError>) {
        let id = self.display_id();
        match result {
            Ok(token) => {
                *self.token.write().unwrap() = token.into();
                *self
                    .failure
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
                self.error_count.store(0, Ordering::Relaxed);
                self.state
                    .store(AccountState::Idle as u8, Ordering::Relaxed);
                info!(target: "ds_core::accounts", "Account {id} logged in");
            }
            Err(e) => {
                let failure = AccountFailure::from_error(&e);
                let count = self.error_count.fetch_add(1, Ordering::Relaxed) + 1;
                let state = if failure.kind.is_terminal() || count >= MAX_ERROR_COUNT {
                    AccountState::Invalid
                } else {
                    AccountState::Error
                };
                self.state.store(state as u8, Ordering::Relaxed);
                warn!(
                    target: "ds_core::accounts",
                    "Account {id} login failed (attempt {count}, now {}): {e}",
                    state.as_str()
                );
                *self
                    .failure
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(failure);
            }
        }
    }

    fn get_total_requests(&self) -> u64 {
        self.window.total_count.load(Ordering::Relaxed)
    }
}

/// 持有期间账号标记为 busy，Drop 时自动释放
pub struct AccountGuard {
    account: Arc<Account>,
}

impl Account {
    /// 该账号的设备身份视图（X-Device-Id + 对应设备的 HIF 令牌）
    pub(crate) fn client(&self) -> DsClient {
        self.client.clone()
    }
}

impl AccountGuard {
    pub fn account(&self) -> &Account {
        &self.account
    }

    /// 取得账号的 `Arc` 句柄
    ///
    /// 需要在守卫被移动（例如移交流处理）之后继续使用账号时使用。
    pub fn account_arc(&self) -> Arc<Account> {
        Arc::clone(&self.account)
    }
}

impl Drop for AccountGuard {
    fn drop(&mut self) {
        // 只有 Busy 状态才释放回 Idle（避免覆盖 Error/Invalid）
        self.account
            .state
            .compare_exchange(
                AccountState::Busy as u8,
                AccountState::Idle as u8,
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .ok();
        self.account
            .last_released
            .store(now_ms(), Ordering::Relaxed);
    }
}

pub struct AccountPool {
    /// 每账号每小时请求上限（0 = 不限制）
    hourly_quota: u64,
    /// 启动时是否用一条 completion 做健康检查（false = 对齐真实客户端启动序列）
    startup_health_check: bool,
    /// 是否复用账号会话（false = 每轮建删，历史行为）
    session_reuse: bool,
    /// 复用模式下会话的空闲回收秒数（0 = 只在进程退出时删除）
    session_idle_secs: u64,
    /// key = display_id (email or mobile), value = Account
    accounts: DashMap<String, Arc<Account>>,
    client: RwLock<Option<DsClient>>,
    solver: RwLock<Option<PowSolver>>,
}

#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    /// 下游客户端错误（网络、API 错误等）
    #[error("客户端错误: {0}")]
    Client(#[from] ClientError),

    /// PoW 计算失败（WASM 执行错误）
    #[error("PoW 计算失败: {0}")]
    Pow(#[from] PowError),

    /// 账号配置验证失败
    #[error("账号配置错误: {0}")]
    Validation(String),

    /// 登录响应显示账号被禁言（`mute_until` 为 Unix 秒）
    #[error("账号被禁言，mute_until={mute_until:?}")]
    Muted { mute_until: Option<f64> },

    /// 启动健康检查失败
    #[error("健康检查失败: {0}")]
    HealthCheck(String),

    /// 账号不存在
    #[error("账号不存在: {0}")]
    NotFound(String),

    /// 账号正在处理请求，暂不能重新登录
    #[error("账号正在使用中: {0}")]
    AccountBusy(String),

    /// 账号池尚未就绪（HTTP 客户端 / PoW 求解器未初始化）
    #[error("账号池尚未就绪")]
    NotReady,
}

impl AccountPool {
    pub fn new(hourly_quota: u64, startup_health_check: bool) -> Self {
        Self {
            hourly_quota,
            startup_health_check,
            // 默认保持历史行为：不复用会话（每轮建删）
            session_reuse: false,
            session_idle_secs: 0,
            accounts: DashMap::new(),
            client: RwLock::new(None),
            solver: RwLock::new(None),
        }
    }

    /// 配置会话复用策略（链式调用，默认关闭）
    #[must_use]
    pub const fn with_session_reuse(mut self, reuse: bool, idle_secs: u64) -> Self {
        self.session_reuse = reuse;
        self.session_idle_secs = idle_secs;
        self
    }

    /// 回收会话：`max_idle = None` 表示全部回收（进程退出时用），
    /// 否则只回收空闲超过该时长的会话。返回回收数量。
    ///
    /// 只会删除**本代理自己缓存**的会话；正在流式传输中的会话不在此列
    /// （它们在 `Chat::active_sessions` 里，由流结束时的清理逻辑负责）。
    pub async fn reap_sessions(&self, max_idle: Option<Duration>) -> usize {
        let mut reaped = 0;
        for account in self.snapshot() {
            if reap_cached_session(&account, max_idle).await {
                reaped += 1;
            }
        }
        reaped
    }

    /// 当前账号的快照
    ///
    /// 遍历时会跨 await 发网络请求：先复制 `Arc` 再释放 DashMap 分片锁，
    /// 否则同时进行的增删账号会在分片写锁上阻塞工作线程。
    fn snapshot(&self) -> Vec<Arc<Account>> {
        self.accounts
            .iter()
            .map(|e| Arc::clone(e.value()))
            .collect()
    }

    async fn base_client_solver(&self) -> Result<(DsClient, PowSolver), PoolError> {
        let client = self.client.read().await.clone();
        let solver = self.solver.read().await.clone();
        client.zip(solver).ok_or(PoolError::NotReady)
    }

    /// 让账号池与期望的账号列表一致，返回期望列表中每个账号的状态（按输入顺序）
    ///
    /// - 新账号：登录后加入；
    /// - 凭据变化的账号：用新凭据登录后替换旧账号；
    /// - 凭据未变的账号：保持原状（不重新登录，适合周期性同步）；
    /// - `remove_missing = true` 时移除列表之外的账号。
    ///
    /// 登录失败的账号同样留在池中（Invalid / Error），失败原因见状态里的 `failure`。
    pub async fn sync(
        &self,
        desired: Vec<AccountConfig>,
        remove_missing: bool,
    ) -> Result<Vec<AccountStatus>, PoolError> {
        let (client, solver) = self.base_client_solver().await?;
        let mut seen = std::collections::HashSet::new();
        let desired: Vec<AccountConfig> = desired
            .into_iter()
            .filter(|c| seen.insert(display_id_of(c).to_string()))
            .collect();
        warn_on_shared_device_ids(&desired);

        // 限制并发登录数，避免对 DeepSeek 端和本地连接池造成压力
        let semaphore = Arc::new(Semaphore::new(13));
        let logins = desired.iter().map(|creds| {
            let semaphore = Arc::clone(&semaphore);
            let (client, solver) = (&client, &solver);
            async move {
                let id = display_id_of(creds).to_string();
                let existing = self.accounts.get(&id).map(|e| Arc::clone(e.value()));
                if let Some(existing) = existing.filter(|a| a.creds == *creds) {
                    return existing;
                }
                let account = Arc::new(Account::new(creds.clone(), client));
                let _permit = semaphore.acquire().await.expect("信号量未关闭");
                account.record_login(login(&account, solver, self.startup_health_check).await);
                if let Some(old) = self.accounts.insert(id, Arc::clone(&account)) {
                    tokio::spawn(async move {
                        reap_cached_session(&old, None).await;
                    });
                }
                account
            }
        });
        let accounts = join_all(logins).await;

        if remove_missing {
            for id in self
                .accounts
                .iter()
                .map(|e| e.key().clone())
                .collect::<Vec<_>>()
            {
                if !seen.contains(&id) {
                    self.remove_account(&id)?;
                }
            }
        }

        Ok(accounts
            .iter()
            .map(|a| AccountStatus::from_account(a, self.hourly_quota))
            .collect())
    }

    /// 移除账号
    ///
    /// 正在处理的请求持有账号的 `Arc`，会正常跑完；缓存的复用会话在后台删除。
    pub fn remove_account(&self, id: &str) -> Result<String, PoolError> {
        let (_, removed) = self
            .accounts
            .remove(id)
            .ok_or_else(|| PoolError::NotFound(id.to_string()))?;
        info!(target: "ds_core::accounts", "Account {id} removed");
        tokio::spawn(async move {
            reap_cached_session(&removed, None).await;
        });
        Ok(id.to_string())
    }

    /// 重新登录指定账号（忙碌中的账号除外），返回登录后的状态
    pub async fn relogin(&self, id: &str) -> Result<AccountStatus, PoolError> {
        let account = self
            .accounts
            .get(id)
            .map(|e| Arc::clone(e.value()))
            .ok_or_else(|| PoolError::NotFound(id.to_string()))?;
        if account.is_busy() {
            return Err(PoolError::AccountBusy(id.to_string()));
        }
        let (_, solver) = self.base_client_solver().await?;
        account.record_login(login(&account, &solver, self.startup_health_check).await);
        Ok(AccountStatus::from_account(&account, self.hourly_quota))
    }

    /// 取指定账号：忙碌时最多等待 `wait`，其它不可用状态立即返回原因
    pub async fn acquire(
        &self,
        id: &str,
        wait: Duration,
    ) -> Result<AccountGuard, AccountUnavailable> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let account = self
                .accounts
                .get(id)
                .map(|e| Arc::clone(e.value()))
                .ok_or(AccountUnavailable::NotFound)?;
            match account.state() {
                AccountState::Idle => {
                    if !account.within_quota(self.hourly_quota) {
                        return Err(AccountUnavailable::QuotaExhausted {
                            retry_after_secs: account.window.retry_after_secs(self.hourly_quota),
                        });
                    }
                    if account
                        .state
                        .compare_exchange(
                            AccountState::Idle as u8,
                            AccountState::Busy as u8,
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                        )
                        .is_ok()
                    {
                        account.record_request(self.hourly_quota);
                        return Ok(AccountGuard { account });
                    }
                }
                AccountState::Busy => {
                    if tokio::time::Instant::now() >= deadline {
                        return Err(AccountUnavailable::Busy);
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                AccountState::Error => return Err(AccountUnavailable::Recovering),
                AccountState::Invalid => {
                    return Err(account
                        .failure()
                        .map_or(AccountUnavailable::Recovering, AccountUnavailable::Failed));
                }
            }
        }
    }

    /// 获取空闲最久的可用账号，带等待：无可用账号时最多等待 `timeout_ms` 毫秒
    pub async fn get_account_with_wait(&self, timeout_ms: u64) -> Option<AccountGuard> {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
        loop {
            if let Some(g) = self.get_account() {
                return Some(g);
            }
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    }

    /// 获取空闲最久的可用账号（不等待，立即返回）
    ///
    /// 遍历所有账号，选冷却已过且空闲时间最长的那个，最大化每次使用间隔。
    /// DashMap 无锁读，不阻塞并发请求。
    pub fn get_account(&self) -> Option<AccountGuard> {
        if self.accounts.is_empty() {
            return None;
        }

        let now_ms = now_ms();

        let mut best: Option<Arc<Account>> = None;
        let mut best_idle = i64::MIN;

        for entry in &self.accounts {
            let account = entry.value();
            if !account.is_available() {
                continue;
            }
            // 超出每小时配额的账号本窗口内不再分配（0 = 不限制）
            if !account.within_quota(self.hourly_quota) {
                debug!(
                    target: "ds_core::accounts",
                    "Account {} quota exhausted (used={}, limit={}), skipping",
                    account.display_id(), account.window.used(), self.hourly_quota
                );
                continue;
            }
            let idle = now_ms - account.last_released.load(Ordering::Relaxed);
            if idle > best_idle {
                best_idle = idle;
                best = Some(Arc::clone(account));
            }
        }

        let account = best?;
        account
            .state
            .compare_exchange(
                AccountState::Idle as u8,
                AccountState::Busy as u8,
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .ok()?;
        account.record_request(self.hourly_quota);
        debug!(
            target: "ds_core::accounts",
            "Account {} allocated for request (used_this_window={}, total={}, idle_ms={})",
            account.display_id(),
            account.window.used(),
            account.get_total_requests(),
            now_ms - account.last_released.load(Ordering::Relaxed)
        );
        Some(AccountGuard { account })
    }

    /// 获取所有账号的详细状态
    pub fn account_statuses(&self) -> Vec<AccountStatus> {
        self.accounts
            .iter()
            .map(|entry| AccountStatus::from_account(entry.value(), self.hourly_quota))
            .collect()
    }

    /// 获取所有账号的详细状态（含统计信息）
    pub fn account_statuses_detailed(&self) -> Vec<AccountStatus> {
        self.accounts
            .iter()
            .map(|entry| AccountStatus::from_account(entry.value(), self.hourly_quota))
            .collect()
    }

    /// 存储 client 和 solver 供恢复任务使用
    pub async fn set_client_solver(&self, client: DsClient, solver: PowSolver) {
        *self.client.write().await = Some(client);
        *self.solver.write().await = Some(solver);
    }

    /// 标记账号为 Error 状态（请求失败时调用）
    pub fn mark_error(&self, email_or_mobile: &str) {
        if let Some(entry) = self.accounts.get(email_or_mobile) {
            let account = entry.value();
            // 只从 Busy 转到 Error（避免覆盖 Invalid）
            account
                .state
                .compare_exchange(
                    AccountState::Busy as u8,
                    AccountState::Error as u8,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .ok();
            warn!(target: "ds_core::accounts", "Account {} marked as Error", account.display_id());
        }
    }

    /// 启动后台恢复任务（每 60 秒）
    ///
    /// - Error 账号重新登录（连续失败 `MAX_ERROR_COUNT` 次后置 Invalid）；
    /// - 禁言到期的 Invalid 账号再试一次登录；
    /// - 复用模式下回收空闲会话。
    pub fn start_recovery_task(self: &Arc<Self>) {
        let pool = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_mins(1)).await;

                let Ok((_, solver)) = pool.base_client_solver().await else {
                    continue;
                };
                for account in pool.snapshot() {
                    let due = match account.state() {
                        AccountState::Error => true,
                        AccountState::Invalid => {
                            account.failure().is_some_and(|f| f.mute_expired())
                        }
                        AccountState::Idle | AccountState::Busy => false,
                    };
                    if due {
                        account.record_login(
                            login(&account, &solver, pool.startup_health_check).await,
                        );
                    }
                }

                // 0 = 只在进程退出时删除
                if pool.session_reuse && pool.session_idle_secs > 0 {
                    pool.reap_sessions(Some(Duration::from_secs(pool.session_idle_secs)))
                        .await;
                }
            }
        });
    }
}

/// 删除账号缓存的复用会话（`max_idle = None` 表示无条件），返回是否删除了会话
async fn reap_cached_session(account: &Account, max_idle: Option<Duration>) -> bool {
    let Some(session_id) = account.take_reapable_session(max_idle) else {
        return false;
    };
    let id = account.display_id();
    match account
        .client()
        .delete_session(&account.token(), &session_id)
        .await
    {
        Ok(()) => {
            debug!(target: "ds_core::accounts", "session reaped: account={id}, session={session_id}");
            true
        }
        Err(e) => {
            warn!(target: "ds_core::accounts", "session reap failed: account={id}, session={session_id}: {e}");
            false
        }
    }
}

/// 检测多个账号共用同一个 `device_id` 并告警
///
/// 设备指纹是**设备级**的，上游用它做关联与画像。实测：同一个 `device_id` 下
/// 挂多个账号、累计数百次请求后，这些账号会被禁言（`biz_code=5`）。
/// 这里不阻止启动（避免破坏既有配置），但必须让用户看到风险。
fn warn_on_shared_device_ids(creds: &[AccountConfig]) {
    let mut by_device: std::collections::HashMap<&str, Vec<&str>> =
        std::collections::HashMap::new();
    for c in creds {
        let device = c.device_id.trim();
        if device.is_empty() {
            continue;
        }
        let id = if c.email.is_empty() {
            c.mobile.as_str()
        } else {
            c.email.as_str()
        };
        by_device.entry(device).or_default().push(id);
    }

    for (device, accounts) in by_device {
        if accounts.len() > 1 {
            let prefix: String = device.chars().take(12).collect();
            warn!(
                target: "ds_core::accounts",
                "{} accounts share the same device_id ({}…): {}. \
                 The device fingerprint is used by upstream for correlation; \
                 sharing it across accounts increases the risk of muting. \
                 Capture a separate device_id per account (one browser profile each).",
                accounts.len(), prefix, accounts.join(", ")
            );
        }
    }
}

/// 账号展示标识：优先 email，回退 mobile
fn display_id_of(creds: &AccountConfig) -> &str {
    if creds.email.is_empty() {
        &creds.mobile
    } else {
        &creds.email
    }
}

/// 账号的 X-Device-Id
///
/// - 有数美 `device_id` 时按其派生：稳定、且**每个账号各不相同**（对齐真实客户端
///   「一个浏览器 profile 一个设备」）；
/// - 显式配置了全局 `client_device_id` 时以配置为准（多账号共用一台设备的场景）；
/// - 都没有时回退到客户端自身的设备身份。
fn account_x_device_id(creds: &AccountConfig, client: &DsClient) -> String {
    if !creds.device_id.trim().is_empty() {
        return super::client::derive_device_uuid(
            format!("ds-free-api:x-device-id:{}", creds.device_id.trim()).as_bytes(),
        );
    }
    client.device_id().to_string()
}

/// 用账号自己的设备身份登录，返回可用的令牌
///
/// 登录 → 禁言早检 → check_device（令牌轮换）→ 可选的启动健康检查。
async fn login(
    account: &Account,
    solver: &PowSolver,
    startup_health_check: bool,
) -> Result<String, PoolError> {
    let creds = &account.creds;
    let client = &account.client;
    // 验证：email 和 mobile 至少一个非空
    if creds.email.is_empty() && creds.mobile.is_empty() {
        return Err(PoolError::Validation(
            "email 和 mobile 不能同时为空".to_string(),
        ));
    }

    // 真实客户端在启动时就取好该设备的 HIF 令牌；这里同样预热，
    // 失败不阻断（与客户端轮询失败时的行为一致）
    client.warm_up_hif().await;

    let login_payload = LoginPayload {
        email: creds.email.clone(),
        mobile: creds.mobile.clone(),
        password: creds.password.clone(),
        area_code: creds.area_code.clone(),
        device_id: creds.device_id.clone(),
        os: client.client_os().to_string(),
    };

    let login_data = client.login(&login_payload).await?;
    debug!(
        target: "ds_core::client",
        "登录响应: code={}, msg={}, user_id={}, email={:?}, mobile={:?}, muted={:?}, mute_until={:?}",
        login_data.code,
        login_data.msg,
        login_data.user.id,
        login_data.user.email,
        login_data.user.mobile_number,
        login_data.user.chat.as_ref().map(|c| c.is_muted),
        login_data.user.chat.as_ref().and_then(|c| c.mute_until),
    );

    // 禁言早检：登录响应即带 chat.is_muted/mute_until，无需等 health_check
    // 的一次完整 completion 才暴露（禁言账号 health_check 必然失败）。
    if let Some(chat) = &login_data.user.chat
        && chat.is_muted != 0
    {
        error!(
            target: "ds_core::accounts",
            "Account {} is muted until {:?} (detected at login)",
            display_id_of(creds),
            chat.mute_until
        );
        return Err(PoolError::Muted {
            mute_until: chat.mute_until,
        });
    }

    let mut token = login_data.user.token;

    // 设备校验 / 令牌轮换：真实客户端登录成功后立即调用
    match client.check_device(&token).await {
        Ok(data) => {
            if let Some(rotate) = data.rotate.as_ref() {
                match super::client::extract_rotate_token(rotate) {
                    Some(new_token) => {
                        debug!(
                            target: "ds_core::accounts",
                            "Account {} token rotated via check_device",
                            display_id_of(creds)
                        );
                        token = new_token;
                    }
                    None => debug!(
                        target: "ds_core::accounts",
                        "Account {} check_device rotate 形态未知，保持原令牌: {}",
                        display_id_of(creds),
                        rotate
                    ),
                }
            } else {
                debug!(
                    target: "ds_core::accounts",
                    "Account {} check_device ok (no rotation)",
                    display_id_of(creds)
                );
            }
        }
        // check_device 失败不阻断初始化（真实客户端亦非关键路径）
        Err(e) => debug!(
            target: "ds_core::accounts",
            "Account {} check_device failed (ignored): {}",
            display_id_of(creds),
            e
        ),
    }

    let display_id = display_id_of(creds);

    // 健康检查：创建临时 session → 发送 test completion → 删除 session
    //
    // `startup_health_check = false` 时整段跳过：真实客户端启动只建会话、不发消息，
    // 而账号可用性已由「登录成功 + 禁言早检（biz_code 5）」保证。
    if startup_health_check {
        let session_id = client.create_session(&token).await?;
        if let Err(e) =
            health_check(&token, &session_id, client, solver, "default", display_id).await
        {
            // 即使健康检查失败也要清理 session
            if let Err(cleanup_err) = client.delete_session(&token, &session_id).await {
                log::warn!(
                    target: "ds_core::accounts",
                    "健康检查失败后清理 session {session_id} 也失败: {cleanup_err}"
                );
            }
            return Err(e);
        }
        if let Err(e) = client.delete_session(&token, &session_id).await {
            log::warn!(
                target: "ds_core::accounts",
                "健康检查后清理 session {session_id} 失败: {e}"
            );
        }
    } else {
        debug!(
            target: "ds_core::accounts",
            "Account {display_id} 跳过启动健康检查（startup_health_check = false）"
        );
    }

    Ok(token)
}

/// 健康检查用的中性提示词池
///
/// 早期实现固定发「只回复\`Hello, world!\`」——这是**所有部署共用的一个常量字符串**，
/// 上游只要按 prompt 聚类就能把大量账号关联到同一个客户端。这里每次随机取一条，
/// 既保留「账号能否正常完成一次推理」的检查能力，又不再留下全局指纹。
const HEALTH_CHECK_PROMPTS: [&str; 5] = [
    "你好",
    "1+1 等于几？",
    "用一句话介绍一下你自己",
    "今天适合做什么？",
    "帮我想一个周末的小计划",
];

/// 随机取一条健康检查提示词（时间戳低位做选择，无需引入随机数依赖）
fn health_check_prompt() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos() as usize);
    HEALTH_CHECK_PROMPTS[nanos % HEALTH_CHECK_PROMPTS.len()].to_string()
}

async fn health_check(
    token: &str,
    session_id: &str,
    client: &DsClient,
    solver: &PowSolver,
    model_type: &str,
    display_id: &str,
) -> Result<(), PoolError> {
    let start = std::time::Instant::now();
    let challenge = client
        .create_pow_challenge(token, "/api/v0/chat/completion")
        .await?;

    let result = solver.solve(&challenge)?;
    let pow_header = result.to_header();

    let payload = CompletionPayload {
        chat_session_id: session_id.to_string(),
        parent_message_id: None,
        model_type: model_type.to_string(),
        prompt: health_check_prompt(),
        ref_file_ids: vec![],
        thinking_enabled: false,
        search_enabled: false,
        action: None,
        source: super::client::COMPLETION_SOURCE,
        preempt: false,
    };

    let mut stream = client.completion(token, &pow_header, &payload).await?;
    // 消费流并检查是否收到正常 SSE（健康账号应有 ready/response 事件）
    let mut data = Vec::new();
    while let Some(chunk) = stream.try_next().await? {
        data.extend_from_slice(&chunk);
    }

    let text = String::from_utf8_lossy(&data);

    // 检测账号是否异常（muted / 限流等）
    if text.contains(r#""biz_code":"#) {
        error!(
            target: "ds_core::accounts",
            "health_check 检测到业务错误: account={}, response={}",
            display_id,
            text.lines().find(|l| l.contains("biz_code")).unwrap_or(&text)
        );
        return Err(PoolError::HealthCheck("账号异常(muted/limited)".into()));
    }

    // 检查 SSE 流是否正常结束
    if !text.contains(r#""FINISHED""#) && !text.contains(r#""INCOMPLETE""#) {
        return Err(PoolError::HealthCheck("SSE 流未正常结束".into()));
    }

    debug!(
        target: "ds_core::accounts",
        "health_check 完成 model_type={} account={} elapsed={:?}",
        model_type, display_id, start.elapsed()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试用客户端：HIF 关闭，设备身份由 api_base 派生（不发起网络请求）
    fn test_client() -> DsClient {
        DsClient::new(
            "https://example.invalid/api/v0".to_string(),
            "https://example.invalid/x.wasm".to_string(),
            super::super::client::ClientIdentity::default(),
            &super::super::client::HifConfig {
                enabled: false,
                ..Default::default()
            },
            super::super::client::EmulationProfile::default(),
            None,
        )
    }

    fn account(email: &str, device_id: &str) -> AccountConfig {
        AccountConfig {
            email: email.to_string(),
            mobile: String::new(),
            area_code: String::new(),
            password: "pw".to_string(),
            device_id: device_id.to_string(),
        }
    }

    fn business(code: i64) -> PoolError {
        PoolError::Client(ClientError::Business {
            code,
            msg: String::new(),
        })
    }

    #[test]
    fn login_failures_are_classified() {
        let kind = |e: &PoolError| AccountFailure::from_error(e).kind;
        assert_eq!(kind(&business(2)), FailureKind::InvalidCredentials);
        assert_eq!(kind(&business(5)), FailureKind::Muted);
        assert_eq!(kind(&business(10)), FailureKind::Banned);
        assert_eq!(kind(&business(11)), FailureKind::DeviceRejected);
        assert_eq!(kind(&business(42)), FailureKind::Rejected);
        assert_eq!(
            kind(&PoolError::Client(ClientError::Status {
                status: 202,
                body: String::new()
            })),
            FailureKind::Blocked
        );
        assert_eq!(
            kind(&PoolError::Muted {
                mute_until: Some(1.5)
            }),
            FailureKind::Muted
        );
        assert_eq!(AccountFailure::from_error(&business(11)).biz_code, Some(11));
        // 只有临时错误值得重试
        assert!(!kind(&PoolError::Pow(super::super::PowError::NoSolution)).is_terminal());
        assert!(kind(&business(2)).is_terminal());
    }

    #[test]
    fn record_login_tracks_state_and_failure() {
        let a = Account::new(account("a@example.com", "dev"), &test_client());
        // 临时错误 → Error，留给恢复任务
        a.record_login(Err(PoolError::Pow(super::super::PowError::NoSolution)));
        assert_eq!(a.state(), AccountState::Error);
        assert_eq!(a.failure().map(|f| f.kind), Some(FailureKind::Unavailable));
        // 成功 → Idle，失败记录清空
        a.record_login(Ok("token".into()));
        assert_eq!(a.state(), AccountState::Idle);
        assert!(a.failure().is_none());
        assert_eq!(&*a.token(), "token");
        // 终止性错误 → 立即 Invalid
        a.record_login(Err(business(2)));
        assert_eq!(a.state(), AccountState::Invalid);
        // 临时错误连续 MAX_ERROR_COUNT 次 → Invalid
        let b = Account::new(account("b@example.com", "dev"), &test_client());
        for _ in 0..MAX_ERROR_COUNT {
            b.record_login(Err(PoolError::Pow(super::super::PowError::NoSolution)));
        }
        assert_eq!(b.state(), AccountState::Invalid);
    }

    #[test]
    fn expired_mute_is_due_for_relogin() {
        let failure = |mute_until| {
            AccountFailure::from_error(&PoolError::Muted {
                mute_until: Some(mute_until),
            })
        };
        assert!(failure(1.0).mute_expired());
        assert!(!failure(4_000_000_000.0).mute_expired());
        assert!(!AccountFailure::from_error(&business(2)).mute_expired());
    }

    #[tokio::test]
    async fn acquire_reports_why_a_pinned_account_is_unavailable() {
        let pool = AccountPool::new(1, false);
        pool.accounts
            .insert("a@example.com".to_string(), idle_account("a@example.com"));
        let wait = Duration::from_millis(10);

        assert!(matches!(
            pool.acquire("missing@example.com", wait).await,
            Err(AccountUnavailable::NotFound)
        ));
        let guard = pool
            .acquire("a@example.com", wait)
            .await
            .expect("idle account");
        assert!(matches!(
            pool.acquire("a@example.com", wait).await,
            Err(AccountUnavailable::Busy)
        ));
        drop(guard);
        // 配额 1 已用完
        match pool.acquire("a@example.com", wait).await {
            Err(AccountUnavailable::QuotaExhausted { retry_after_secs }) => {
                assert!(retry_after_secs > 3500 && retry_after_secs <= 3600);
            }
            Err(other) => panic!("expected quota exhaustion, got {other}"),
            Ok(_) => panic!("expected quota exhaustion, got a guard"),
        }

        let invalid = Arc::new(Account::new(
            account("b@example.com", "dev"),
            &test_client(),
        ));
        invalid.record_login(Err(business(11)));
        pool.accounts.insert("b@example.com".to_string(), invalid);
        assert!(matches!(
            pool.acquire("b@example.com", wait).await,
            Err(AccountUnavailable::Failed(AccountFailure {
                kind: FailureKind::DeviceRejected,
                ..
            }))
        ));
    }

    #[test]
    fn per_account_device_identity_is_unique_and_stable() {
        let client = test_client();
        let a1 = account_x_device_id(&account("a@example.com", "shumei-device-a"), &client);
        let a2 = account_x_device_id(&account("a@example.com", "shumei-device-a"), &client);
        let b = account_x_device_id(&account("b@example.com", "shumei-device-b"), &client);
        assert_eq!(a1, a2, "同一账号的设备身份必须稳定");
        assert_ne!(a1, b, "不同账号不得共用同一个 X-Device-Id");
        assert_eq!(a1.len(), 36);
        // 无 device_id 时回退到客户端自身身份
        let fallback = account_x_device_id(&account("c@example.com", ""), &client);
        assert_eq!(fallback, client.device_id());
    }

    #[test]
    fn sliding_window_counts_and_reports_usage() {
        let w = SlidingWindowRateLimiter::new();
        assert_eq!(w.used(), 0);
        assert_eq!(w.record(), 1);
        assert_eq!(w.record(), 2);
        assert_eq!(w.used(), 2);
    }

    #[test]
    fn quota_of_zero_means_unlimited() {
        let a = Account::new(account("a@example.com", "dev"), &test_client());
        for _ in 0..500 {
            a.record_request(0);
        }
        assert!(a.within_quota(0), "0 必须表示不限制");
    }

    #[test]
    fn account_is_blocked_after_reaching_quota() {
        let a = Account::new(account("a@example.com", "dev"), &test_client());
        let limit = 3;
        assert!(a.within_quota(limit));
        a.record_request(limit);
        assert!(a.within_quota(limit), "达到上限前仍可用");
        a.record_request(limit);
        assert!(a.within_quota(limit));
        a.record_request(limit);
        assert!(!a.within_quota(limit), "达到上限后该窗口内不应再被分配");
    }

    #[test]
    fn expired_sliding_window_resets_usage() {
        let w = SlidingWindowRateLimiter::new();
        for _ in 0..5 {
            w.record();
        }
        assert_eq!(w.used(), 5);
        // 手动插入旧时间戳模拟窗口过期
        let now = now_secs();
        let mut ts = w.timestamps.lock().unwrap();
        ts.clear();
        // 插入 1 小时前的时间戳
        for _ in 0..5 {
            ts.push_back(now - WINDOW_SECS - 100);
        }
        drop(ts);
        assert_eq!(w.used(), 0, "窗口过期后用量应视作 0");
        assert_eq!(w.record(), 1, "过期后重新计数应从 1 开始");
    }

    #[test]
    fn shared_device_ids_are_detected() {
        let creds = vec![
            account("a@example.com", "same-device"),
            account("b@example.com", "same-device"),
            account("c@example.com", "own-device"),
        ];
        let mut by_device: std::collections::HashMap<&str, Vec<&str>> =
            std::collections::HashMap::new();
        for c in &creds {
            if !c.device_id.trim().is_empty() {
                by_device
                    .entry(c.device_id.as_str())
                    .or_default()
                    .push(c.email.as_str());
            }
        }
        let shared: Vec<_> = by_device.iter().filter(|(_, v)| v.len() > 1).collect();
        assert_eq!(shared.len(), 1, "应只检出一组共用指纹");
        assert_eq!(shared[0].1.len(), 2);
    }

    /// 复用会话槽：写入 / 读取 / 按 ID 精确清除
    #[test]
    fn cached_session_slot_roundtrip() {
        let account = idle_account("cache@example.com");
        assert!(
            account.cached_session_for(&[1, 2, 3]).is_none(),
            "初始应为空"
        );

        account.put_cached_session("s-1", vec![1, 2], 42);
        assert_eq!(
            account.cached_session_for(&[1, 2, 9]),
            Some(("s-1".to_string(), 42))
        );

        // 不匹配的 ID 不得误删
        account.clear_cached_session("s-other");
        assert!(account.cached_session_for(&[1, 2, 9]).is_some());

        account.clear_cached_session("s-1");
        assert!(account.cached_session_for(&[1, 2, 9]).is_none());
    }

    /// 空闲回收：未超时不动，超时取出；`None` 表示无条件回收
    #[test]
    fn reapable_session_respects_idle_window() {
        let account = idle_account("idle@example.com");
        account.put_cached_session("s-2", vec![7], 9);

        assert!(
            account
                .take_reapable_session(Some(Duration::from_mins(5)))
                .is_none(),
            "刚用过的会话不应被回收"
        );
        assert_eq!(
            account.take_reapable_session(None).as_deref(),
            Some("s-2"),
            "退出时应无条件回收"
        );
        assert!(
            account.cached_session_for(&[1]).is_none(),
            "回收后槽位应清空"
        );
    }

    /// 增量匹配：链前缀一致且只多 1~2 条才算命中
    #[test]
    fn cached_session_matches_only_real_continuations() {
        let account = idle_account("delta@example.com");
        account.put_cached_session("s-9", vec![10, 20], 77);

        // 多一条（客户端只回传新用户消息）→ 命中
        assert_eq!(
            account.cached_session_for(&[10, 20, 30]),
            Some(("s-9".to_string(), 77))
        );
        // 多两条（回传自己的回复 + 新用户消息，官方客户端形态）→ 命中
        assert_eq!(
            account.cached_session_for(&[10, 20, 31, 30]),
            Some(("s-9".to_string(), 77))
        );
        // 前缀不一致（历史被改写 / 换客户端）→ 不命中
        assert_eq!(account.cached_session_for(&[10, 99, 30]), None);
        // 完全相同的链（同一请求重放）→ 不命中，避免把重复内容再发一次
        assert_eq!(account.cached_session_for(&[10, 20]), None);
        // 多出三条以上（客户端跳过了一轮）→ 不命中
        assert_eq!(account.cached_session_for(&[10, 20, 1, 2, 3]), None);
        // 比缓存还短 → 不命中
        assert_eq!(account.cached_session_for(&[10]), None);
    }

    /// 会话策略默认关闭复用，且 `with_session_reuse` 只改策略相关字段
    #[test]
    fn session_reuse_defaults_off() {
        let pool = AccountPool::new(10, true);
        assert!(!pool.session_reuse, "默认必须保持「每轮建删」的历史行为");
        assert_eq!(pool.session_idle_secs, 0);

        let pool = pool.with_session_reuse(true, 900);
        assert!(pool.session_reuse);
        assert_eq!(pool.session_idle_secs, 900);
        assert_eq!(pool.hourly_quota, 10, "其它配置不应被改动");
    }

    /// 空账号池回收会话是安全的空操作
    #[tokio::test]
    async fn reap_sessions_on_empty_pool_is_noop() {
        let pool = AccountPool::new(0, true);
        assert_eq!(pool.reap_sessions(None).await, 0);
    }

    /// 构造一个可用的（Idle）测试账号
    fn idle_account(email: &str) -> Arc<Account> {
        Arc::new(Account {
            token: std::sync::RwLock::new("t".into()),
            email: email.to_string(),
            mobile: String::new(),
            state: AtomicU8::new(AccountState::Idle as u8),
            last_released: AtomicI64::new(0),
            error_count: AtomicU8::new(0),
            failure: Mutex::new(None),
            creds: account(email, "dev"),
            window: SlidingWindowRateLimiter::new(),
            session: Mutex::new(None),
            client: test_client(),
        })
    }

    #[test]
    fn pool_skips_accounts_that_exhausted_their_quota() {
        let pool = AccountPool::new(2, true);
        pool.accounts
            .insert("a@example.com".to_string(), idle_account("a@example.com"));

        // 配额 2：前两次可以拿到账号
        assert!(pool.get_account().is_some(), "第 1 次应可分配");
        assert!(pool.get_account().is_some(), "第 2 次应可分配");
        // 第三次该账号已用尽 → 池中无可用账号
        assert!(
            pool.get_account().is_none(),
            "配额用尽后不应再分配该账号（调用方据此返回 429）"
        );
    }

    #[test]
    fn pool_with_unlimited_quota_never_blocks() {
        let pool = AccountPool::new(0, true);
        pool.accounts
            .insert("a@example.com".to_string(), idle_account("a@example.com"));
        for i in 0..50 {
            assert!(pool.get_account().is_some(), "配额 0 时第 {i} 次也应可分配");
        }
    }

    #[test]
    fn exhausted_account_does_not_block_other_accounts() {
        let pool = AccountPool::new(1, true);
        pool.accounts
            .insert("a@example.com".to_string(), idle_account("a@example.com"));
        pool.accounts
            .insert("b@example.com".to_string(), idle_account("b@example.com"));

        // 两个账号各能用 1 次（顺序取决于「空闲最久」策略）
        assert!(pool.get_account().is_some());
        assert!(pool.get_account().is_some());
        assert!(pool.get_account().is_none(), "两个账号都用尽后应返回 None");
    }

    #[test]
    fn empty_device_ids_are_ignored_by_shared_detection() {
        // 空 device_id 会被上游拒绝登录，但不该在这里被误报为「共用」
        let creds = vec![
            account("a@example.com", ""),
            account("b@example.com", "   "),
        ];
        let mut by_device: std::collections::HashMap<&str, Vec<&str>> =
            std::collections::HashMap::new();
        for c in &creds {
            if !c.device_id.trim().is_empty() {
                by_device.entry(c.device_id.as_str()).or_default().push("x");
            }
        }
        assert!(by_device.is_empty());
    }
}
