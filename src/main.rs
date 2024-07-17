/// This function sets up the terminal for the TUI, runs the main application loop,
/// and restores the terminal state when the application exits.
///
/// # Notes
///
/// - Uses crossterm for terminal manipulation
/// - Creates a ratatui terminal with a CrosstermBackend
/// - Handles errors and restores terminal state on exit
///
/// # TODO
///
/// - Add command line arguments for initial state or configuration
/// - Implement logging for better error tracking
pub mod app;
pub mod blockchain;
pub mod errors;
pub mod handlers;
pub mod ui;

use crate::errors::AppError;
use app::App;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use log::LevelFilter;
use ratatui::{backend::CrosstermBackend, Terminal};
use simplelog::{Config, WriteLogger};
use std::fs::File;
use std::io;

#[tokio::main]
async fn main() -> Result<(), AppError> {
    // Set up logging
    let log_file = File::create("bittensor-rs.log").expect("Failed to create log file");
    WriteLogger::init(LevelFilter::Debug, Config::default(), log_file)
        .expect("Failed to initialize logger");
    // env_logger::init();
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app and run it
    let mut app = App::new()?;
    let res = app.run(&mut terminal).await;

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{:?}", err)
    }

    Ok(())
}
