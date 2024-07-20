///! Documentation for the root input handler
///
/// This function handles user input when in the Root state.
///
/// # Arguments
///
/// * `app` - A mutable reference to the App
/// * `input` - The KeyCode of the user's input
///
/// # TODO
///
/// - Implement actual functionality for root network operations
/// - Add error handling for root network operations
/// Documentation for the root input handler
///
/// This function handles user input when in the Root state.
///
/// # Arguments
///
/// * `app` - A mutable reference to the App
/// * `input` - The KeyCode of the user's input
///
/// # TODO
///
/// - Implement actual functionality for root network operations
/// - Add error handling for root network operations
use crate::app::{App, AppState};
use crate::errors::AppError;
use crossterm::event::KeyCode;

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
