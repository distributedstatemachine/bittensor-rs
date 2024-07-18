use crate::app::{App, AppState};
use bittensor_rs::errors::AppError;
///! Documentation for the subnets input handler
///
/// This function handles user input when in the Subnets state.
///
/// # Arguments
///
/// * `app` - A mutable reference to the App
/// * `input` - The KeyCode of the user's input
///
/// # TODO
///
/// - Implement actual functionality for subnet operations
/// - Add error handling for subnet operations
use crossterm::event::KeyCode;

pub async fn handle_input(app: &mut App, input: KeyCode) -> Result<(), AppError> {
    match input {
        KeyCode::Char('b') => {
            app.state = AppState::Home;
            app.selected_subnet = None;
        }
        KeyCode::Up => {
            if let Some(selected) = app.selected_subnet.as_mut() {
                if *selected > 0 {
                    *selected -= 1;
                }
            } else if !app.subnets.is_empty() {
                app.selected_subnet = Some(0);
            }
        }
        KeyCode::Down => {
            if let Some(selected) = app.selected_subnet.as_mut() {
                if *selected < app.subnets.len() - 1 {
                    *selected += 1;
                }
            } else if !app.subnets.is_empty() {
                app.selected_subnet = Some(0);
            }
        }
        KeyCode::Enter => {
            if let Some(selected) = app.selected_subnet {
                // TODO: Implement subnet selection logic
                println!("Selected subnet: {:?}", app.subnets[selected].kappa);
            }
        }
        KeyCode::Char('l') => {
            if let Some(selected) = app.selected_subnet {
                let netuid = app.subnets[selected].netuid;
                let lock_cost = app.update_subnet_lock_cost(netuid.into(), 1);
                println!("Lock cost for subnet {:?}: {:?}", netuid, lock_cost);
            }
        }
        _ => {}
    }
    Ok(())
}
