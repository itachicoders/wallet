use std::io::{self, stdout, Stdout};
use std::time::Duration;

use crossterm::event::{self, DisableMouseCapture, EnableMouseCapture, Event};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use crate::ui::app::App;

pub struct Tui {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl Tui {
    pub fn new() -> io::Result<Self> {
        let backend = CrosstermBackend::new(stdout());
        let terminal = Terminal::new(backend)?;
        Ok(Self { terminal })
    }

    pub fn enter(&mut self) -> io::Result<()> {
        enable_raw_mode()?;
        execute!(stdout(), EnterAlternateScreen, EnableMouseCapture)?;
        self.terminal.hide_cursor()?;
        self.terminal.clear()?;
        Ok(())
    }

    pub fn exit(&mut self) -> io::Result<()> {
        disable_raw_mode()?;
        execute!(stdout(), LeaveAlternateScreen, DisableMouseCapture)?;
        self.terminal.show_cursor()?;
        Ok(())
    }

    pub async fn run(&mut self, mut app: App) -> io::Result<()> {
        self.enter()?;

        let tick_rate = Duration::from_millis(50);

        while !app.should_exit {
            self.terminal.draw(|f| app.render(f))?;

            if event::poll(tick_rate)? {
                match event::read()? {
                    Event::Key(key) => {
                        app.handle_key(key).await;
                    }
                    Event::Mouse(mouse) => {
                        app.handle_mouse(mouse);
                    }
                    _ => {}
                }
            }
        }

        self.exit()?;
        Ok(())
    }
}
