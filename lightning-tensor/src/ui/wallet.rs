use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

// use crate::blockchain::wallet::Wallet;
// use crate::errors::AppError;
use crate::App;
use bittensor_wallet::keypair::Keypair;
use bittensor_wallet::Wallet;
use bittensor_wallet::WalletError;

// use log::debug;

/// Renders the wallet interface
///
/// # Arguments
///
/// * `f` - A mutable reference to the Frame
/// * `app` - A mutable reference to the App state
/// * `area` - The area of the screen to render the wallet interface
///
pub async fn draw<'a>(f: &mut Frame<'a>, app: &mut App, area: ratatui::layout::Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(10),
            Constraint::Length(3),
        ])
        .split(area);

    let title = Paragraph::new("Wallet Management")
        .style(Style::default().fg(Color::Cyan))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Bittensor Wallet"),
        );
    f.render_widget(title, chunks[0]);

    let wallet_list = render_wallet_list(app);
    f.render_stateful_widget(wallet_list, chunks[1], &mut app.wallet_list_state);

    let wallet_info = render_wallet_info(app);
    f.render_widget(wallet_info, chunks[2]);

    let instructions = Paragraph::new(
        "Press 'c' to create a new wallet, 'r' to refresh balances, Enter to select/deselect, Up/Down to navigate, 'b' to go back"
    )
    .style(Style::default().fg(Color::Gray))
    .block(Block::default().borders(Borders::ALL).title("Instructions"));
    f.render_widget(instructions, chunks[2]);

    if app.input_mode {
        let input_content = if app.is_password_input {
            "*".repeat(app.input_buffer.len())
        } else {
            app.input_buffer.clone()
        };
        let input = Paragraph::new(format!("{}{}", app.input_prompt, input_content))
            .style(Style::default().fg(Color::Yellow))
            .block(Block::default().borders(Borders::ALL).title("Input"));
        f.render_widget(input, chunks[3]);
    } else {
        let messages_guard = app.messages.lock().await;
        let messages: Vec<ListItem> = messages_guard
            .iter()
            .map(|m| ListItem::new(m.as_str()))
            .collect();
        let messages_list =
            List::new(messages).block(Block::default().borders(Borders::ALL).title("Messages"));
        f.render_widget(messages_list, chunks[3]);
    }
}

fn render_wallet_list(app: &App) -> List<'static> {
    let wallet_items: Vec<ListItem> = app
        .wallets
        .iter()
        .enumerate()
        .map(|(index, wallet)| {
            let balance = wallet
                .balance
                .map_or_else(|| "Unknown".to_string(), |b| format!("{:.2}", b));
            let selected = if Some(index) == app.selected_wallet {
                "[x]"
            } else {
                "[ ]"
            };
            ListItem::new(format!(
                "{} {} - Balance: {}",
                selected, wallet.name, balance
            ))
        })
        .collect();

    List::new(wallet_items)
        .block(Block::default().title("Wallets").borders(Borders::ALL))
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ")
}

fn render_wallet_info(app: &App) -> Paragraph<'_> {
    let wallet_info = if let Some(selected_index) = app.selected_wallet {
        if let Some(selected_wallet) = app.wallets.get(selected_index) {
            match get_wallet_keypair(selected_wallet, &app.wallet_password) {
                Ok(keypair) => vec![
                    Line::from(vec![
                        Span::raw("Name: "),
                        Span::styled(&selected_wallet.name, Style::default().fg(Color::Yellow)),
                    ]),
                    Line::from(vec![
                        Span::raw("Address: "),
                        Span::styled(keypair.public.to_string(), Style::default().fg(Color::Cyan)),
                    ]),
                    Line::from(vec![
                        Span::raw("Balance: "),
                        Span::styled(
                            selected_wallet
                                .balance
                                .map_or("Unknown".to_string(), |b| format!("{:.2}", b)),
                            Style::default().fg(Color::Green),
                        ),
                    ]),
                    Line::from(""),
                    Line::from("Press 's' to sign a message"),
                    Line::from("Press 'v' to verify a signature"),
                    Line::from("Press 'd' to delete this wallet"),
                    Line::from("Press 'p' to change the wallet password"),
                ],
                Err(_) => vec![
                    Line::from("Failed to decrypt wallet."),
                    Line::from("Press 'p' to enter the correct password."),
                ],
            }
        } else {
            vec![Line::from("Selected wallet not found")]
        }
    } else {
        vec![
            Line::from("No wallet selected"),
            Line::from("Use Up/Down to navigate and Enter to select a wallet"),
            Line::from("Press 'c' to create a new wallet"),
        ]
    };

    Paragraph::new(wallet_info)
        .block(
            Block::default()
                .title("Wallet Information")
                .borders(Borders::ALL),
        )
        .style(Style::default().fg(Color::White))
        .alignment(Alignment::Left)
}

fn get_wallet_keypair(wallet: &Wallet, password: &str) -> Result<Keypair, WalletError> {
    wallet.get_coldkey(password)
}
