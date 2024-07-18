use ratatui::{
    text::Line,
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::app::App;

pub async fn draw<'a>(f: &mut Frame<'a>, _app: &mut App, area: ratatui::layout::Rect) {
    let root = Paragraph::new(vec![
        Line::from("Root Network View"),
        Line::from(""),
        Line::from("1. List Root Info"),
        Line::from("2. Set Weights"),
        Line::from("3. View Senate"),
        Line::from(""),
        Line::from("Press 'b' to go back"),
    ])
    .block(Block::default().title("Root Network").borders(Borders::ALL));
    f.render_widget(root, area);
}
