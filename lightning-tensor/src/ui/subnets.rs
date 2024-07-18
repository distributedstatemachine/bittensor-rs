///! Documentation for the Subnets draw function
///
/// This function renders the Subnets view of the TUI.
///
/// # TODO
///
/// - Implement actual subnet data display
/// - Add interactive elements for subnet operations
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    text::Line,
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame,
};

use crate::app::App;

pub async fn draw<'a>(f: &mut Frame<'a>, app: &mut App, area: ratatui::layout::Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(80), Constraint::Percentage(20)].as_ref())
        .split(area);

    let subnet_items: Vec<ListItem> = app
        .subnets
        .iter()
        .map(|subnet| {
            ListItem::new(Line::from(format!(
                "Subnet {:?}: {:?}",
                <codec::Compact<u16> as Into<u16>>::into(subnet.netuid),
                subnet.netuid
            )))
        })
        .collect();

    let subnets_list = List::new(subnet_items)
        .block(Block::default().title("Subnets").borders(Borders::ALL))
        .highlight_style(Style::default().fg(Color::Yellow))
        .highlight_symbol("> ");

    let mut list_state = ListState::default();
    list_state.select(app.selected_subnet);

    f.render_stateful_widget(subnets_list, chunks[0], &mut list_state);

    let instructions = Paragraph::new(vec![
        Line::from("↑/↓: Navigate"),
        Line::from("Enter: Select subnet"),
        Line::from("l: View lock cost"),
        Line::from("b: Back to home"),
    ])
    .block(Block::default().title("Instructions").borders(Borders::ALL));

    f.render_widget(instructions, chunks[1]);
}
