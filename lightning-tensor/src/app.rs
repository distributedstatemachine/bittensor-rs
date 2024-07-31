use crate::errors::AppError;
use bittensor_rs::subnets::types::SubnetInfo;
use bittensor_rs::Subtensor;
use bittensor_wallet::Wallet;
use futures::executor::block_on;
use std::error::Error;

use crate::ui::AnimationState;
use crossterm::event::{self, Event, KeyCode};
use log::debug;
use ratatui::backend::Backend;
use ratatui::widgets::ListState;
use ratatui::{Frame, Terminal};
use sp_core::crypto::AccountId32;
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
    WalletCreated(Result<Wallet, Box<dyn Error + Send + Sync>>),
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
    pub subtensor: Subtensor,
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

        let config_file = Self::get_config_path().unwrap();
        let coldkey = Self::read_coldkey_from_config(&config_file).unwrap();

        Self {
            state: AppState::Home,
            should_quit: false,
            subtensor: block_on(Subtensor::new(DEFAULT_NETWORK_URL, &coldkey)).unwrap_or_else(
                |e| {
                    panic!("Failed to initialize Subtensor: {}", e);
                },
            ),
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

        let config_file = Self::get_config_path()?;
        let coldkey = Self::read_coldkey_from_config(&config_file)?;
        // let coldkey = Self::read_coldkey_from_config(&config_file)?;

        let mut app = App {
            state: AppState::Home,
            should_quit: false,
            subtensor: block_on(Subtensor::new(DEFAULT_NETWORK_URL, &coldkey)).unwrap_or_else(
                |e| {
                    panic!("Failed to initialize Subtensor: {}", e);
                },
            ),
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
        self.wallets = self.detect_wallets(&self.wallet_dir);
        if !self.wallets.is_empty() {
            self.wallet_list_state.select(Some(0));
        }
        Ok(())
    }

    /// Detects and loads wallets from the specified directory.
    ///
    /// # Arguments
    ///
    /// * `wallet_dir` - A reference to a PathBuf representing the directory to search for wallets.
    ///
    /// # Returns
    ///
    /// A Vec<Wallet> containing all successfully loaded wallets.
    ///
    /// # Example
    ///
    /// ```
    /// let wallet_dir = PathBuf::from("/path/to/wallets");
    /// let wallets = app.detect_wallets(&wallet_dir);
    /// ```
    fn detect_wallets(&self, wallet_dir: &PathBuf) -> Vec<Wallet> {
        let mut wallets: Vec<Wallet> = Vec::new();

        // Attempt to read the contents of the wallet directory
        if let Ok(entries) = std::fs::read_dir(wallet_dir) {
            for entry in entries.flatten() {
                if let Ok(file_type) = entry.file_type() {
                    // Check if the entry is a directory
                    if file_type.is_dir() {
                        let wallet_name = entry.file_name().to_string_lossy().into_owned();
                        let wallet_path = entry.path();

                        // Attempt to create a new Wallet instance
                        let wallet = Wallet::new(&wallet_name, wallet_path);
                        {
                            wallets.push(wallet);
                            log::info!("Loaded wallet: {}", wallet_name);
                        }
                    }
                }
            }
        }

        wallets
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

    fn get_config_path() -> Result<PathBuf, AppError> {
        let current_dir = std::env::current_dir().map_err(|e| {
            AppError::ConfigError(format!("Failed to get current directory: {}", e))
        })?;

        let config_file = current_dir.join("config.toml");

        if !config_file.exists() {
            return Err(AppError::ConfigError(
                "config.toml not found in workspace root".into(),
            ));
        }

        Ok(config_file)
    }

    // TODO: Move to utlity Crate
    fn read_coldkey_from_config(config_file: &PathBuf) -> Result<String, AppError> {
        let config_str = std::fs::read_to_string(config_file)
            .map_err(|e| AppError::ConfigError(format!("Failed to read config file: {}", e)))?;

        let config: toml::Value = toml::from_str(&config_str)
            .map_err(|e| AppError::ConfigError(format!("Failed to parse TOML: {}", e)))?;

        config["coldkey"]
            .as_str()
            .ok_or_else(|| AppError::ConfigError("Coldkey not found in config".into()))
            .map(String::from)
    }
}
