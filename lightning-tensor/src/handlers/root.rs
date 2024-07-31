//! This module contains handlers for root network-related user inputs.

use crate::app::{App, AppState};
use crate::errors::AppError;
use crossterm::event::KeyCode;

/// Handles user input when in the Root state.
///
/// This function processes user input specific to root network operations.
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
/// # TODO
///
/// - Implement actual functionality for root network operations
/// - Add error handling for root network operations

pub async fn handle_input(app: &mut App, input: KeyCode) -> Result<(), AppError> {
    match input {
        KeyCode::Char('b') => app.state = AppState::Home,
        KeyCode::Char('1') => {
            // TODO: Implement list root info functionality
            println!("List root info");
        }
        KeyCode::Char('2') => {
            // TODO: Implement set weights functionality
            println!("Set weights");
        }
        KeyCode::Char('3') => {
            // TODO: Implement view senate functionality
            println!("View senate");
        }
        _ => {}
    }
    Ok(())
}
