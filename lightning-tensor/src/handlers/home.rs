/// Documentation for the home input handler
///
/// This function handles user input when in the Home state.
///
/// # Arguments
///
/// * `app` - A mutable reference to the App
/// * `input` - The KeyCode of the user's input
///
/// # TODO
///
/// - Add more sophisticated input handling
/// - Implement help functionality
use crate::app::{App, AppState};
use bittensor_rs::errors::AppError;
use crossterm::event::KeyCode;

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
