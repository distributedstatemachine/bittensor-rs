use crate::blockchain::subnets::SubnetInfo;
use crate::blockchain::wallet::detect_wallets;
use crate::blockchain::wallet::Wallet;
use crate::blockchain::BittensorApi;
use crate::errors::AppError;
use crate::handlers::wallet::SendableResult;
use crate::ui::AnimationState;
use crossterm::event::{self, Event, KeyCode};
use log::debug;
// use parking_lot::Mutex;
use ratatui::backend::Backend;
use ratatui::widgets::ListState;
use ratatui::{Frame, Terminal};
use sp_core::crypto::AccountId32;
// use tokio::task::futures;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::Mutex;

/// Enum representing various wallet operations
///
/// This enum is used to communicate the results of asynchronous wallet operations
/// between different parts of the application.
///
/// ```
#[derive(Debug)]
pub enum WalletOperation {
    /// Represents the result of loading a wallet address
    AddressLoaded(Result<String, AppError>),
    /// Represents the result of creating a new wallet
    WalletCreated(SendableResult),
    /// Represents the result of changing a wallet password
    PasswordChanged(Result<(), AppError>),
}

// TODO: Consider adding more wallet operations like WalletDeleted, WalletUpdated, etc.
// TODO: Implement custom error types for more specific error handling in wallet operations.

/// Enum representing the different states of the application
#[derive(Clone, Copy, PartialEq)]
pub enum AppState {
    Home,
    Subnets,
    Root,
    Wallet,
}

/// Main application struct
pub struct App {
    pub state: AppState,
    pub should_quit: bool,
    pub bittensor_api: BittensorApi,
    pub subnets: Vec<SubnetInfo<AccountId32>>,
    pub selected_subnet: Option<usize>,
    pub messages: Arc<Mutex<Vec<String>>>,
    pub input_mode: bool,
    pub input_prompt: String,
    pub input_callback: Arc<dyn Fn(&mut App, String) + Send + Sync>,

    pub wallets: Vec<Wallet>,
    pub wallet_list_state: ListState,
    pub wallet_password: String,
    pub selected_wallet: Option<usize>,
    pub animation_state: AnimationState,
    pub wallet_op_sender: Sender<WalletOperation>,
    pub wallet_op_receiver: Receiver<WalletOperation>,
    pub input_buffer: String,
    pub is_password_input: bool,
    pub wallet_dir: PathBuf,
}

const DEFAULT_NETWORK_URL: &str = "ws://localhost:9946";

impl Default for App {
    fn default() -> Self {
        // Create a channel for wallet operations
        let (wallet_op_sender, wallet_op_receiver) = channel(100);
        let wallet_dir = dirs::home_dir()
            .ok_or_else(|| AppError::ConfigError("Unable to determine home directory".into()))
            .unwrap()
            .join(".bittensor-rs")
            .join("wallets");

        Self {
            state: AppState::Home,
            should_quit: false,
            bittensor_api: BittensorApi::new(DEFAULT_NETWORK_URL)
                .expect("Failed to initialize BittensorApi"),
            subnets: Vec::new(),
            selected_subnet: None,
            messages: Arc::new(Mutex::new(Vec::new())),
            input_mode: false,
            input_prompt: String::new(),
            input_callback: Arc::new(Box::new(|_: &mut App, _: String| {}))
                as Arc<dyn Fn(&mut App, String) + Send + Sync>,
            wallets: Vec::new(),
            wallet_list_state: ListState::default(),
            wallet_password: String::new(),
            selected_wallet: None,
            animation_state: AnimationState::new(),
            wallet_op_sender,
            wallet_op_receiver,
            input_buffer: String::new(),
            is_password_input: false,
            wallet_dir,
        }
    }
}

impl App {
    /// Creates a new instance of the App
    pub fn new() -> Result<Self, AppError> {
        let wallet_dir = dirs::home_dir()
            .ok_or_else(|| AppError::ConfigError("Unable to determine home directory".into()))?
            .join(".bittensor-rs")
            .join("wallets");

        let mut app = App {
            state: AppState::Home,
            should_quit: false,
            bittensor_api: BittensorApi::new(DEFAULT_NETWORK_URL)
                .expect("Failed to initialize BittensorApi"),
            subnets: Vec::new(),
            selected_subnet: None,
            messages: Arc::new(Mutex::new(Vec::new())),
            input_mode: false,
            input_prompt: String::new(),
            input_callback: Arc::new(Box::new(|_: &mut App, _: String| {}))
                as Arc<dyn Fn(&mut App, String) + Send + Sync>,
            wallets: Vec::new(),
            wallet_list_state: ListState::default(),
            wallet_password: String::new(),
            selected_wallet: None,
            animation_state: AnimationState::new(),
            wallet_op_sender: channel(100).0,
            wallet_op_receiver: channel(100).1,
            input_buffer: String::new(),
            is_password_input: false,
            wallet_dir,
        };

        app.detect_and_load_wallets()?;

        Ok(app)
    }

    /// Fetches the list of subnets from the blockchain
    pub async fn fetch_subnets(&mut self) -> Result<(), AppError> {
        self.subnets = self.bittensor_api.get_subnets_info().await?;
        Ok(())
    }

    /// Fetches the lock cost for a specific subnet
    pub async fn fetch_subnet_lock_cost(&mut self, netuid: u16) -> Result<u64, AppError> {
        let subnet_info = self.bittensor_api.get_subnet_info(netuid).await?;
        Ok(subnet_info.burn.into())
    }

    /// Updates the lock cost for a specific subnet in the local list
    pub fn update_subnet_lock_cost(&mut self, netuid: u16, lock_cost: u64) {
        if let Some(subnet) = self.subnets.iter_mut().find(|s| s.netuid == netuid.into()) {
            subnet.burn = lock_cost.into();
        }
    }

    /// Renders the user interface for the application
    pub fn ui(&mut self, f: &mut Frame) {
        let future = crate::ui::draw(f, self);
        futures::executor::block_on(future);
    }

    pub fn selected_wallet(&self) -> Option<&Wallet> {
        self.selected_wallet
            .and_then(|index| self.wallets.get(index))
    }

    fn detect_and_load_wallets(&mut self) -> Result<(), AppError> {
        self.wallets = detect_wallets(&self.wallet_dir);
        if !self.wallets.is_empty() {
            self.wallet_list_state.select(Some(0));
        }
        Ok(())
    }

    pub async fn refresh_wallet_balances(&mut self) -> Result<(), AppError> {
        for wallet in &mut self.wallets {
            wallet.fetch_balance().await?;
        }
        Ok(())
    }

    /// Runs the main application loop
    pub async fn run(&mut self, terminal: &mut Terminal<impl Backend>) -> Result<(), AppError> {
        loop {
            terminal.draw(|f| {
                let future = crate::ui::draw(f, self);
                futures::executor::block_on(future)
            })?;
            if event::poll(std::time::Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    debug!(
                        "Received key event: {:?}, input_mode: {}",
                        key, self.input_mode
                    );
                    if self.input_mode {
                        match key.code {
                            KeyCode::Enter => {
                                let input = std::mem::take(&mut self.input_buffer);
                                let callback = std::mem::replace(
                                    &mut self.input_callback,
                                    Arc::new(|_, _| {}),
                                );
                                callback(self, input);
                            }
                            KeyCode::Char(c) => {
                                self.input_buffer.push(c);
                            }
                            KeyCode::Backspace => {
                                self.input_buffer.pop();
                            }
                            KeyCode::Esc => {
                                self.input_mode = false;
                                self.is_password_input = false;
                                self.input_buffer.clear();
                                self.messages
                                    .lock()
                                    .await
                                    .push("Wallet creation cancelled".to_string());
                            }
                            _ => {}
                        }
                    } else {
                        match self.state {
                            AppState::Home => {
                                crate::handlers::home::handle_input(self, key.code).await
                            }
                            AppState::Subnets => {
                                crate::handlers::subnets::handle_input(self, key.code).await
                            }
                            AppState::Root => {
                                crate::handlers::root::handle_input(self, key.code).await
                            }
                            AppState::Wallet => {
                                crate::handlers::wallet::handle_input(self, key.code).await
                            }
                        }?;
                    }

                    if self.should_quit {
                        return Ok(());
                    }
                }
            }
        }
    }
}
