use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};
use std::{
    future::{self, Future},
    pin::Pin,
    time::{Duration, Instant},
};

use crate::app::AppState;
use crate::App;

mod root;
mod subnets;
mod wallet;

/// The duration of each frame in the animation
const ANIMATION_FRAME_DURATION: Duration = Duration::from_millis(100);

/// Struct to hold the animation state
pub struct AnimationState {
    pub frame: usize,
    pub last_update: Instant,
}

impl Default for AnimationState {
    fn default() -> Self {
        Self::new()
    }
}

impl AnimationState {
    pub fn new() -> Self {
        Self {
            frame: 0,
            last_update: Instant::now(),
        }
    }

    pub fn update(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_update) >= ANIMATION_FRAME_DURATION {
            self.frame = (self.frame + 1) % 4; // 4 frames for rotation
            self.last_update = now;
        }
    }
}

pub fn draw<'a>(f: &'a mut Frame, app: &'a mut App) -> Pin<Box<dyn Future<Output = ()> + 'a>> {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([Constraint::Length(3), Constraint::Min(0)].as_ref())
        .split(f.size());
    let title = Paragraph::new("⚡TENSOR")
        .style(
            Style::default()
                .fg(Color::LightYellow)
                .add_modifier(Modifier::BOLD),
        )
        .alignment(ratatui::layout::Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, chunks[0]);

    match app.state {
        AppState::Home => Box::pin({
            draw_home(f, app, chunks[1]);
            future::ready(())
        }),
        AppState::Subnets => Box::pin(subnets::draw(f, app, chunks[1])),
        AppState::Root => Box::pin(root::draw(f, app, chunks[1])),
        AppState::Wallet => Box::pin(wallet::draw(f, app, chunks[1])),
    }
}

pub fn draw_home(f: &mut Frame, app: &mut App, area: Rect) {
    app.animation_state.update();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)].as_ref())
        .split(area);

    let ascii_art = get_animated_ascii_art(app.animation_state.frame);

    let ascii_art_widget = Paragraph::new(ascii_art.join("\n"))
        .style(Style::default().fg(Color::Cyan))
        .alignment(ratatui::layout::Alignment::Center)
        .block(Block::default().borders(Borders::NONE));

    f.render_widget(ascii_art_widget, chunks[0]);

    let welcome_text = vec![
        Line::from(vec![
            // Span::styled("Collective Inte ", Style::default().fg(Color::White)),
            Span::styled(
                "Collective Intelligence at the speed of ⚡",
                Style::default()
                    .fg(Color::Yellow) // Changed from Cyan to Yellow for lightning color
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("[ s ] ", Style::default().fg(Color::Yellow)),
            Span::raw("Subnets"),
            Span::styled("   [ r ] ", Style::default().fg(Color::Yellow)),
            Span::raw("Root"),
            Span::styled("   [ w ] ", Style::default().fg(Color::Yellow)),
            Span::raw("Wallet"),
            Span::styled("   [ q ] ", Style::default().fg(Color::Yellow)),
            Span::raw("Quit"),
        ]),
    ];

    let home = Paragraph::new(welcome_text)
        .style(Style::default().fg(Color::White))
        .alignment(ratatui::layout::Alignment::Center)
        .wrap(Wrap { trim: true })
        .block(Block::default().borders(Borders::ALL).title("Home"));

    f.render_widget(home, chunks[1]);
}

fn get_animated_ascii_art(frame: usize) -> Vec<String> {
    let base_art = vec![
        "     ○───○───○     ",
        "    ╱ ╲ ╱ ╲ ╱ ╲    ",
        "   ○───○───○───○   ",
        "  ╱ ╲ ╱ ╲ ╱ ╲ ╱ ╲  ",
        " ○───○───○───○───○ ",
        "  ╲ ╱ ╲ ╱ ╲ ╱ ╲ ╱  ",
        "   ○───○───○───○   ",
        "    ╲ ╱ ╲ ╱ ╲ ╱    ",
        "     ○───○───○     ",
    ];

    let spin_chars = ['○', '◔', '◑', '◕', '●', '◕', '◑', '◔'];
    let current_char = spin_chars[frame];

    base_art
        .into_iter()
        .map(|line| {
            line.chars()
                .map(|c| if c == '○' { current_char } else { c })
                .collect()
        })
        .collect()
}
