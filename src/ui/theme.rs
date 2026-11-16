use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::BorderType;

pub struct Theme {
    pub surface: Color,
    pub surface_card: Color,
    pub surface_card_high: Color,
    pub primary: Color,
    pub on_primary: Color,
    pub secondary: Color,
    pub error: Color,
    pub text_primary: Color,
    pub text_secondary: Color,
    pub border: Color,
    pub focus_border: Color,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            surface: Color::Rgb(18, 18, 20),
            surface_card: Color::Rgb(28, 28, 32),
            surface_card_high: Color::Rgb(38, 38, 45),
            primary: Color::Rgb(0, 218, 198),
            on_primary: Color::Rgb(0, 50, 45),
            secondary: Color::Rgb(128, 222, 234),
            error: Color::Rgb(255, 128, 128),
            text_primary: Color::Rgb(240, 240, 245),
            text_secondary: Color::Rgb(160, 160, 175),
            border: Color::Rgb(55, 55, 68),
            focus_border: Color::Rgb(0, 218, 198),
        }
    }
}

impl Theme {
    pub fn card_style(&self) -> Style {
        Style::default().bg(self.surface_card).fg(self.text_primary)
    }

    pub fn card_border_type(&self) -> BorderType {
        BorderType::Rounded
    }

    pub fn pill_active(&self) -> Style {
        Style::default()
            .bg(self.primary)
            .fg(self.on_primary)
            .add_modifier(Modifier::BOLD)
    }

    pub fn pill_inactive(&self) -> Style {
        Style::default()
            .bg(self.surface_card_high)
            .fg(self.text_secondary)
    }

    pub fn header_style(&self) -> Style {
        Style::default()
            .fg(self.primary)
            .add_modifier(Modifier::BOLD)
    }
}
