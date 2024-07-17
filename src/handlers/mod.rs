/// Documentation for the Events struct
///
/// This struct manages input events and ticks for the TUI.
///
/// # Fields
///
/// * `rx` - A receiver for events (input or tick)
///
/// # Methods
///
/// * `new()` - Creates a new Events instance and spawns an event loop
/// * `next()` - Waits for and returns the next event
///
/// # TODO
///
/// - Add support for mouse events if needed
/// - Implement error handling for event processing
use crossterm::event::{self, Event as CEvent, KeyCode};

use std::time::Duration;
use tokio::sync::mpsc;

pub mod home;
pub mod root;
pub mod subnets;
pub mod wallet;

pub enum Event<I> {
    Input(I),
    Tick,
}

pub struct Events {
    rx: mpsc::Receiver<Event<KeyCode>>,
}

impl Default for Events {
    fn default() -> Self {
        Self::new()
    }
}

impl Events {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel(100);
        let tick_rate = Duration::from_millis(200);

        tokio::spawn(async move {
            let mut last_tick = tokio::time::Instant::now();
            loop {
                let timeout = tick_rate
                    .checked_sub(last_tick.elapsed())
                    .unwrap_or_else(|| Duration::from_secs(0));

                if event::poll(timeout).unwrap() {
                    if let CEvent::Key(key) = event::read().unwrap() {
                        tx.send(Event::Input(key.code)).await.unwrap();
                    }
                }

                if last_tick.elapsed() >= tick_rate {
                    tx.send(Event::Tick).await.unwrap();
                    last_tick = tokio::time::Instant::now();
                }
            }
        });

        Events { rx }
    }

    pub async fn next(&mut self) -> Option<Event<KeyCode>> {
        self.rx.recv().await
    }
}
