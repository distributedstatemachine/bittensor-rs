use crate::app::{App, AppState, WalletOperation};
use crate::errors::AppError;
use bittensor_wallet::Wallet;
use crossterm::event::KeyCode;
use log::{debug, error};
use sp_core::sr25519::Signature as Sr25519Signature;
use std::error::Error;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::Mutex;

#[derive(Debug)]
pub struct SendableResult(pub Result<Wallet, Box<dyn Error + Send + Sync>>);

pub async fn handle_input(app: &mut App, input: KeyCode) -> Result<(), AppError> {
    match input {
        KeyCode::Char('c') => create_wallet(app).await?,
        KeyCode::Char('r') => refresh_balances(app).await?,
        KeyCode::Char('d') => delete_wallet(app).await?,
        KeyCode::Char('p') => change_wallet_password(app).await?,
        KeyCode::Char('s') => sign_message(app).await?,
        KeyCode::Char('v') => verify_signature(app).await?,
        KeyCode::Up => {
            if let Some(selected) = app.wallet_list_state.selected() {
                let amount = app.wallets.len();
                if selected > 0 {
                    app.wallet_list_state.select(Some(selected - 1));
                } else {
                    app.wallet_list_state.select(Some(amount - 1));
                }
            }
        }
        KeyCode::Down => {
            if let Some(selected) = app.wallet_list_state.selected() {
                let amount = app.wallets.len();
                if selected >= amount - 1 {
                    app.wallet_list_state.select(Some(0));
                } else {
                    app.wallet_list_state.select(Some(selected + 1));
                }
            }
        }
        KeyCode::Enter => {
            if let Some(selected) = app.wallet_list_state.selected() {
                app.selected_wallet = Some(selected);
            }
        }
        KeyCode::Char('b') => app.state = AppState::Home,
        _ => {}
    }
    Ok(())
}

/// Creates a new wallet based on user input.
///
/// # Arguments
///
/// * `app` - A mutable reference to the application state.
///
/// # Returns
///
/// * `Result<(), AppError>` - Ok if the operation is successful, or an AppError if it fails.
///
/// # Example
///
/// ```
/// let mut app = App::new();
/// create_wallet(&mut app).await?;
/// ```
async fn create_wallet(app: &mut App) -> Result<(), AppError> {
    debug!("Entering create_wallet function");

    app.input_mode = true;
    app.is_password_input = false;
    app.input_prompt = "Enter wallet name: ".to_string();
    app.input_buffer.clear();

    debug!(
        "Set input_mode to true and input_prompt to '{}'",
        app.input_prompt
    );

    let name_callback = Arc::new(Box::new(move |app: &mut App, _: String| {
        let name: String = app.input_buffer.clone();
        debug!("Input callback triggered with name: {}", name);
        app.input_mode = true;
        app.is_password_input = true;
        app.input_prompt = "Enter password: ".to_string();
        app.input_buffer.clear();

        debug!(
            "Set input_prompt to '{}' and is_password_input to true",
            app.input_prompt
        );

        let password_callback = Arc::new(Box::new(move |app: &mut App, password: String| {
            debug!("Password input callback triggered");
            let name_clone: String = name.clone();
            let password_clone: String = password.clone();
            let wallet_op_sender = app.wallet_op_sender.clone();

            let (log_tx, mut log_rx) = mpsc::channel::<String>(100);
            let log_tx: Arc<Mutex<mpsc::Sender<String>>> = Arc::new(Mutex::new(log_tx));

            let messages: Arc<Mutex<Vec<String>>> = Arc::clone(&app.messages);
            tokio::spawn(async move {
                while let Some(log) = log_rx.recv().await {
                    let mut messages = messages.lock().await;
                    messages.push(log);
                }
            });

            let messages: Arc<Mutex<Vec<String>>> = Arc::clone(&app.messages);
            let name_for_message: String = name_clone.clone();
            tokio::spawn(async move {
                let mut messages = messages.lock().await;
                messages.push(format!("Creating wallet: {}...", name_for_message));
            });
            app.input_mode = false;
            app.is_password_input = false;
            app.input_buffer.clear();

            let wallet_dir = app.wallet_dir.clone();
            tokio::spawn(async move {
                debug!("Spawning wallet creation task");

                // Attempt to create the wallet
                let mut wallet = Wallet::new(&name_clone, wallet_dir);
                let creation_result = wallet.create_new_wallet(12, &password_clone);

                debug!("Wallet creation result: {:?}", creation_result);

                debug!("Wallet creation result: {:?}", creation_result);
                debug!("Attempted to create wallet with name: {}", name_clone);

                // Send the result through the wallet operation channel
                if let Err(send_error) = wallet_op_sender
                    .send(WalletOperation::WalletCreated(
                        creation_result
                            .map(|_| wallet)
                            .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>),
                    ))
                    .await
                {
                    error!("Failed to send wallet creation result: {:?}", send_error);

                    // Log the failure
                    let name_for_error: String = name_clone.clone(); // Clone the name again for use in this closure
                    let guard = log_tx.lock().await;
                    if let Err(log_error) = guard
                        .send(format!("Failed to create wallet: {}", name_for_error))
                        .await
                    {
                        error!(
                            "Failed to send log message for wallet {}: {:?}",
                            name_for_error, log_error
                        );
                    }
                }

                // TODO: Implement proper error handling for lock acquisition failure
                // TODO: Consider implementing a retry mechanism for failed wallet creations
                // TODO: Evaluate the need for a timeout mechanism in wallet creation process
            });

            debug!("Set input_mode and is_password_input to false");
        }));

        app.input_callback = password_callback;
    }));

    app.input_callback = name_callback;

    debug!("Exiting create_wallet function");
    Ok(())
}

async fn delete_wallet(app: &mut App) -> Result<(), AppError> {
    if let Some(selected) = app.wallet_list_state.selected() {
        if selected < app.wallets.len() {
            let wallet = app.wallets.remove(selected);
            let messages = Arc::clone(&app.messages);
            tokio::spawn(async move {
                let mut messages = messages.lock().await;
                messages.push(format!("Deleted wallet: {}", wallet.name));
            });
            if app.wallets.is_empty() {
                app.wallet_list_state.select(None);
            } else {
                app.wallet_list_state
                    .select(Some(selected.min(app.wallets.len() - 1)));
            }
        }
    } else {
        let messages = Arc::clone(&app.messages);
        tokio::spawn(async move {
            let mut messages = messages.lock().await;
            messages.push("No wallet selected".to_string());
        });
    }
    Ok(())
}

/// Signs a message using the selected wallet.
///
/// # Arguments
///
/// * `app` - A mutable reference to the application state.
///
/// # Returns
///
/// * `Result<(), AppError>` - Ok if the operation is successful, or an AppError if it fails.
///
/// # Example
///
/// ```
/// let mut app = App::new();
/// sign_message(&mut app).await?;
/// ```
async fn sign_message(app: &mut App) -> Result<(), AppError> {
    if let Some(selected) = app.wallet_list_state.selected() {
        if selected < app.wallets.len() {
            let wallet = app.wallets[selected].clone();
            app.input_mode = true;
            app.input_prompt = "Enter message to sign: ".to_string();
            app.input_callback = Arc::new(Box::new(move |app: &mut App, message: String| {
                let wallet_clone = wallet.clone();
                let message_clone = message.clone();
                app.input_mode = true;
                app.input_prompt = "Enter password: ".to_string();
                app.input_callback = Arc::new(Box::new(move |app: &mut App, password: String| {
                    let messages = Arc::clone(&app.messages);
                    let wallet_clone2 = wallet_clone.clone();
                    let message_clone2 = message_clone.clone();
                    tokio::spawn(async move {
                        let mut messages = messages.lock().await;
                        match wallet_clone2.get_active_hotkey(&password) {
                            Ok(keypair) => {
                                match keypair.sign(message_clone2.as_bytes(), &password) {
                                    Ok(signature) => {
                                        // Convert the signature to a byte array before encoding
                                        let signature_bytes: [u8; 64] =
                                            *<Sr25519Signature as AsRef<[u8; 64]>>::as_ref(
                                                &signature,
                                            );
                                        messages.push(format!(
                                            "Signature: {}",
                                            hex::encode(signature_bytes)
                                        ));
                                    }
                                    Err(e) => {
                                        messages.push(format!("Failed to sign message: {:?}", e));
                                    }
                                }
                            }
                            Err(e) => {
                                messages.push(format!("Failed to get active hotkey: {:?}", e));
                            }
                        }
                    });
                    app.input_mode = false;
                }));
            }));
        }
    } else {
        let messages = Arc::clone(&app.messages);
        tokio::spawn(async move {
            let mut messages = messages.lock().await;
            messages.push("No wallet selected".to_string());
        });
    }
    Ok(())
}

// TODO: Implement error handling for failed message signing
// TODO: Consider adding a timeout for the signing process
// TODO: Implement a way to cancel the signing process if it takes too long

// TODO: Implement error handling for failed message signing
// TODO: Consider adding a timeout for the signing process
// TODO: Implement a way to cancel the signing process if it takes too long

/// Verifies a signature using the selected wallet.
///
/// # Arguments
///
/// * `app` - A mutable reference to the application state.
///
/// # Returns
///
/// * `Result<(), AppError>` - Ok if the operation is successful, or an AppError if it fails.
///
/// # Example
///
/// ```
/// let mut app = App::new();
/// verify_signature(&mut app).await?;
/// ```
async fn verify_signature(app: &mut App) -> Result<(), AppError> {
    if let Some(selected) = app.wallet_list_state.selected() {
        if selected < app.wallets.len() {
            let wallet: Wallet = app.wallets[selected].clone();
            app.input_mode = true;
            app.input_prompt = "Enter message: ".to_string();
            app.input_callback = Arc::new(move |app: &mut App, message: String| {
                let message_clone: String = message.clone();
                let wallet_clone: Wallet = wallet.clone();
                app.input_mode = true;
                app.input_prompt = "Enter signature (hex): ".to_string();
                app.input_callback = Arc::new(move |app: &mut App, signature: String| {
                    let message_clone2: String = message_clone.clone();
                    let signature_clone: String = signature.clone();
                    let wallet_clone2: Wallet = wallet_clone.clone();
                    app.input_mode = true;
                    app.input_prompt = "Enter password: ".to_string();
                    app.input_callback = Arc::new(move |app: &mut App, password: String| {
                        let messages: Arc<Mutex<Vec<String>>> = Arc::clone(&app.messages);
                        let message_clone3: String = message_clone2.clone();
                        let signature_clone2: String = signature_clone.clone();
                        let wallet_clone3: Wallet = wallet_clone2.clone();
                        let password_clone: String = password.clone();
                        tokio::spawn(async move {
                            let mut messages = messages.lock().await;
                            match hex::decode(&signature_clone2) {
                                Ok(decoded_signature) => {
                                    match wallet_clone3.verify(
                                        message_clone3.as_bytes(),
                                        &decoded_signature,
                                        &password_clone,
                                    ) {
                                        Ok(is_valid) => {
                                            messages
                                                .push(format!("Signature is valid: {}", is_valid));
                                        }
                                        Err(e) => {
                                            messages.push(format!(
                                                "Failed to verify signature: {:?}",
                                                e
                                            ));
                                        }
                                    }
                                }
                                Err(e) => {
                                    messages.push(format!("Failed to decode signature: {:?}", e));
                                }
                            }
                        });
                        app.input_mode = false;
                    });
                });
            });
        }
    } else {
        let messages: Arc<Mutex<Vec<String>>> = Arc::clone(&app.messages);
        tokio::spawn(async move {
            let mut messages = messages.lock().await;
            messages.push("No wallet selected".to_string());
        });
    }
    Ok(())
}

// TODO: Implement error handling for failed signature verification
// TODO: Consider adding a timeout for the verification process
// TODO: Implement a way to cancel the verification process if it takes too long

async fn prompt_password(app: &mut App) -> Result<(), AppError> {
    app.input_mode = true;
    app.input_prompt = "Enter wallet password: ".to_string();
    app.input_callback = Arc::new(Box::new(|app: &mut App, password: String| {
        app.wallet_password = password;
        let messages = Arc::clone(&app.messages);
        tokio::spawn(async move {
            let mut messages = messages.lock().await;
            messages.push("Password updated".to_string());
        });
        app.input_mode = false;
    }));
    Ok(())
}

async fn refresh_balances(app: &mut App) -> Result<(), AppError> {
    for wallet in app.wallets.iter_mut() {
        wallet.fetch_balance().await?;
    }
    Ok(())
}
async fn change_wallet_password(app: &mut App) -> Result<(), AppError> {
    if let Some(selected) = app.wallet_list_state.selected() {
        if selected < app.wallets.len() {
            let wallet = app.wallets[selected].clone();
            app.input_mode = true;
            app.input_prompt = "Enter current password: ".to_string();
            app.input_buffer.clear();
            app.is_password_input = true;

            app.input_callback = Arc::new(Box::new(move |app: &mut App, old_password: String| {
                let wallet_clone = wallet.clone();
                app.input_mode = true;
                app.input_prompt = "Enter new password: ".to_string();
                app.input_buffer.clear();

                app.input_callback =
                    Arc::new(Box::new(move |app: &mut App, new_password: String| {
                        let mut wallet_clone2 = wallet_clone.clone();
                        let old_password_clone = old_password.clone();
                        let wallet_op_sender = app.wallet_op_sender.clone();

                        tokio::spawn(async move {
                            let result = wallet_clone2
                                .change_password(&old_password_clone, &new_password)
                                .await;
                            let _ = wallet_op_sender
                                .send(WalletOperation::PasswordChanged(
                                    result.map_err(AppError::from),
                                ))
                                .await;
                        });

                        app.input_mode = false;
                        app.is_password_input = false;
                        let messages = Arc::clone(&app.messages);
                        tokio::spawn(async move {
                            let mut messages = messages.lock().await;
                            messages.push("Password change initiated. Please wait...".to_string());
                        });
                    }));
            }));
        }
    } else {
        let messages = Arc::clone(&app.messages);
        tokio::spawn(async move {
            let mut messages = messages.lock().await;
            messages.push("No wallet selected".to_string());
        });
    }
    Ok(())
}
