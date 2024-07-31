//! This module contains handlers for home screen-related user inputs.

use crate::app::{App, AppState};
use crate::errors::AppError;
use crossterm::event::KeyCode;

/// Handles user input when in the Home state.
///
/// This function processes user input specific to the home screen operations.
///
/// # Arguments
///
/// * `app` - A mutable reference to the App
/// * `input` - The KeyCode of the user's input
///
/// # Returns
///
/// * `Result<(), AppError>` - Ok if the input was handled successfully, or an error if something went wrong
///
/// # Errors
///
/// This function will return an error if:
/// - There's an issue updating the app state
/// - Any operation triggered by user input fails
///
pub async fn handle_input(app: &mut App, input: KeyCode) -> Result<(), AppError> {
    match input {
        KeyCode::Char('q') => app.should_quit = true,
        KeyCode::Char('s') => app.state = AppState::Subnets,
        KeyCode::Char('r') => app.state = AppState::Root,
        KeyCode::Char('w') => app.state = AppState::Wallet,
        _ => {}
    }
    Ok(())
}
