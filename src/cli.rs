use crate::{hasher::deterministic_hash, prelude::*, secure_vec::*};
use std::io::Read;
use termion::{
    color::{self, *},
    cursor,
    event::Key,
    input::TermRead,
    raw::IntoRawMode,
    screen::AlternateScreen,
};

macro_rules! color {
    ( $color:ident, $fmt_str:literal $( , $arg:expr )* ) => {
        format!("{}{}{}", color::Fg($color), format!($fmt_str $( , $arg )*), color::Fg(color::Reset))
    }
}

macro_rules! goto {
    ( $x:expr, $y:expr ) => {
        cursor::Goto($x, $y)
    };
}

macro_rules! left {
    ( $n:expr ) => {
        cursor::Left($n)
    };
}

macro_rules! proportion {
    ( $frac:literal, $value:expr ) => {
        ($frac * $value as f64).round() as u16
    };
}

const CONFIRM_HEADER: &str = "Confirm your password: ";
const ENTER_HEADER: &str = "Enter your password: ";
const LENGTH_HEADER: &str = "Length: ";
const STRENGTH_HEADER: &str = "Strength: ";
const SUGGESTION_HEADER: &str = "Suggestion: ";
const WARNING_HEADER: &str = "Warning: ";

struct CliFrontEnd<W, F>
where
    W: std::io::Write,
    F: Fn(SecureBytes) -> Option<bool>,
{
    // term_width: u16,
    border_b: u16,
    border_l: u16,
    border_r: u16,
    border_t: u16,
    cache_is_match: Option<bool>,
    cache_length: String,
    cache_strength: String,
    cache_suggestion: String,
    cache_warning: String,
    chars: Vec<char>,
    confirm: bool,
    enter_message_len: u16,
    key_matches: F,
    prompt_goto: cursor::Goto,
    prompt_width: u16,
    prompt_x: u16,
    prompt_y: u16,
    pw_len_goto: cursor::Goto,
    pw_portion_width: u16,
    score_goto: cursor::Goto,
    screen: W,
    sugg_goto: cursor::Goto,
    term_height: u16,
    warning_goto: cursor::Goto,
}

impl<W, F> CliFrontEnd<W, F>
where
    W: std::io::Write,
    F: Fn(SecureBytes) -> Option<bool>,
{
    pub fn new(confirm: bool, term_width: u16, term_height: u16, screen: W, key_matches: F) -> Self {
        let border_l = proportion!(0.05, term_width);
        let border_r = proportion!(0.95, term_width);
        let border_t = proportion!(0.05, term_height);
        let border_b = proportion!(0.95, term_height);

        //
        let mid = proportion!(0.5, term_height);

        let enter_message_len = 23;
        let prompt_width = proportion!(0.7, term_width);
        let pw_portion_width = prompt_width - enter_message_len;

        let prompt_x = (term_width - prompt_width) / 2;
        let prompt_y = mid - 2;
        let prompt_goto = goto!(prompt_x, prompt_y);
        let pw_len_goto = goto!(prompt_x, mid - 1);
        let score_goto = goto!(prompt_x, mid);
        let warning_goto = goto!(prompt_x, mid + 1);
        let sugg_goto = goto!(prompt_x, mid + 2);

        //
        Self {
            // term_width,
            border_b,
            border_l,
            border_r,
            border_t,
            cache_is_match: None,
            cache_length: String::new(),
            cache_strength: String::new(),
            cache_suggestion: String::new(),
            cache_warning: String::new(),
            chars: Vec::with_capacity(1024),
            confirm,
            enter_message_len: 23,
            key_matches,
            prompt_goto,
            prompt_width,
            prompt_x,
            prompt_y,
            pw_len_goto,
            pw_portion_width,
            score_goto,
            screen,
            sugg_goto,
            term_height,
            warning_goto,
        }
    }

    fn goto_backspace(&self) -> Option<cursor::Goto> {
        match self.chars.len() {
            0 => None,
            len if len <= (self.prompt_width - self.enter_message_len) as usize => {
                Some(goto!(self.prompt_x + self.enter_message_len + len as u16, self.prompt_y))
            }
            _ => None,
        }
    }

    fn goto_asterisk(&self) -> Option<cursor::Goto> {
        match self.chars.len() {
            len if len < (self.prompt_width - self.enter_message_len) as usize => {
                Some(goto!(self.prompt_x + self.enter_message_len + len as u16, self.prompt_y))
            }
            _ => None,
        }
    }

    // TODO refactor later
    fn score(&self) -> u8 {
        zxcvbn::zxcvbn(&self.chars.iter().collect::<String>(), &[]).unwrap().score()
    }
    fn feedback(&self) -> std::option::Option<zxcvbn::feedback::Feedback> {
        zxcvbn::zxcvbn(&self.chars.iter().collect::<String>(), &[])
            .unwrap()
            .feedback()
            .clone()
    }

    fn clean(screen: &mut W, cache: &mut String, goto: cursor::Goto) {
        Self::cached_write(
            screen,
            cache,
            |cache| 0 < cache.len(),
            |cache| cache.clear(),
            &format!("{}{}", goto, (0..cache.len()).map(|_| ' ').collect::<String>()),
        )
    }

    fn cached_write_color<C, D1, D2>(screen: &mut W, cache: &mut String, color: C, goto: cursor::Goto, header: D1, desc: D2)
    where
        C: color::Color,
        D1: std::fmt::Display,
        D2: std::fmt::Display,
    {
        let uncolored_content = format!("{}{:>23}{}", goto, header, desc);
        if cache != &uncolored_content {
            Self::clean(screen, cache, goto);

            *cache = uncolored_content;
            let colored_content = color!(color, "{}", cache);
            write!(screen, "{}", colored_content).unwrap();
        }
    }

    fn cached_write<F1, F2>(screen: &mut W, cache: &mut String, cache_check: F1, if_stale: F2, content: &String)
    where
        F1: Fn(&String) -> bool,
        F2: Fn(&mut String) -> (),
    {
        if cache != content && cache_check(cache) {
            *cache = content.clone();
            write!(screen, "{}", cache).unwrap();
            if_stale(cache);
        }
    }

    fn diag(&mut self) {
        let term_height_ok = 5 <= self.term_height;
        if term_height_ok {
            Self::cached_write_color(
                &mut self.screen,
                &mut self.cache_length,
                Reset,
                self.pw_len_goto,
                LENGTH_HEADER,
                self.chars.len(),
            );
        }
        if 0 < self.chars.len() && term_height_ok {
            //clean!(pw_len_goto, cache_length);
            Self::cached_write_color(
                &mut self.screen,
                &mut self.cache_length,
                Reset,
                self.pw_len_goto,
                LENGTH_HEADER,
                self.chars.len(),
            );

            let desc = match self.score() {
                0 => color!(Red, "SUX"),
                1 => color!(Red, "VERY BAD"),
                2 => color!(Yellow, "BAD"),
                3 => color!(Reset, "GOOD"),
                4 => color!(Green, "EXCELLENT"),
                _ => unreachable!(),
            };
            Self::cached_write_color(
                &mut self.screen,
                &mut self.cache_strength,
                Reset,
                self.score_goto,
                STRENGTH_HEADER,
                desc,
            );

            let (sugg, warning) = match self.feedback() {
                Some(sugg) => (
                    format!("{}", sugg.suggestions()[0]),
                    match sugg.warning() {
                        Some(warning) => format!("{}", warning),
                        None => String::new(),
                    },
                ),
                None => (String::new(), String::new()),
            };
            Self::cached_write_color(
                &mut self.screen,
                &mut self.cache_suggestion,
                Yellow,
                self.sugg_goto,
                SUGGESTION_HEADER,
                sugg,
            );
            Self::cached_write_color(
                &mut self.screen,
                &mut self.cache_warning,
                Yellow,
                self.warning_goto,
                WARNING_HEADER,
                warning,
            );
        }
    }

    fn mask_char(matches: bool) -> char {
        match matches {
            true => '\u{2713}',
            false => '\u{10102}',
        }
    }

    fn rewrite_prompt<C>(
        screen: &mut W,
        chars: &Vec<char>,
        color: C,
        confirm: bool,
        mask: char,
        prompt_goto: cursor::Goto,
        pw_portion_width: u16,
    ) where
        C: color::Color,
    {
        write!(
            screen,
            "{}{}",
            prompt_goto,
            color!(
                color,
                "{}{}",
                format!(
                    "{:>23}{}{}",
                    match confirm {
                        true => CONFIRM_HEADER,
                        false => ENTER_HEADER,
                    },
                    (0..chars.len()).map(|_| mask).collect::<String>(),
                    (chars.len()..pw_portion_width as usize).map(|_| '_').collect::<String>()
                ),
                left!(pw_portion_width)
            )
        )
        .unwrap()
    }

    fn matches(&self) -> Option<bool> {
        (self.key_matches)(self.chars.iter().copied().collect::<String>().as_bytes().to_vec().into())
    }

    fn color_match(&mut self) {
        macro_rules! rewrite {
            ( $color:ident, $mask:literal ) => {
                Self::rewrite_prompt(
                    &mut self.screen,
                    &self.chars,
                    $color,
                    self.confirm,
                    Self::mask_char($mask),
                    self.prompt_goto,
                    self.pw_portion_width,
                )
            };
        }

        let new_matches = self.matches();
        match self.cache_is_match == new_matches {
            true => (),
            false => {
                self.cache_is_match = new_matches;
                match new_matches {
                    Some(true) => rewrite!(Green, true),
                    Some(false) => rewrite!(Red, false),
                    None => rewrite!(Reset, true),
                }
            }
        }
    }

    pub fn handle_keys(mut self) -> SecureBytes {
        if 7 <= self.term_height {
            draw_border(&mut self.screen, self.border_l, self.border_r, self.border_t, self.border_b);
        }

        Self::rewrite_prompt(
            &mut self.screen,
            &self.chars,
            Reset,
            self.confirm,
            Self::mask_char(true),
            self.prompt_goto,
            self.pw_portion_width,
        );
        for key_down in std::io::stdin().keys() {
            //
            match key_down.unwrap() {
                //
                Key::Char('\n') => break,
                //
                Key::Ctrl('c') => panic!(),

                //
                Key::Backspace if 0 < self.chars.len() => {
                    if let Some(goto) = self.goto_backspace() {
                        write!(
                            &mut self.screen,
                            "{}{}{}{}",
                            goto,
                            left!(1),
                            match self.cache_is_match {
                                Some(true) => color!(Green, "_"),
                                Some(false) => color!(Red, "_"),
                                None => color!(Reset, "_"),
                            },
                            left!(1)
                        )
                        .unwrap();
                    }
                    self.chars.pop().unwrap();
                    self.diag();
                    self.color_match();
                }
                //
                Key::Char(chr) => {
                    if let Some(goto) = self.goto_asterisk() {
                        write!(
                            &mut self.screen,
                            "{}{}",
                            goto,
                            match self.cache_is_match {
                                Some(true) => color!(Green, "{}", Self::mask_char(true)),
                                Some(false) => color!(Red, "{}", Self::mask_char(false)),
                                None => color!(Reset, "{}", Self::mask_char(true)),
                            },
                        )
                        .unwrap();
                    }
                    self.chars.push(chr);
                    self.diag();
                    self.color_match();
                }
                //
                _ => (),
            }
        }

        self.screen.flush().unwrap();

        self.chars.into_iter().collect::<String>().as_bytes().to_vec().into()
    }
}

pub fn get_password(confirm_password: bool) -> CsyncResult<CryptoSecureBytes> {
    let isatty = isatty::stderr_isatty();
    let initial = deterministic_hash(match isatty {
        true => run(false, |_| None),
        false => {
            let mut buffer = Vec::new();
            std::io::stdin().read_to_end(&mut buffer).unwrap();

            match confirm_password {
                true => {
                    let newline_indices: Vec<_> = buffer
                        .iter()
                        .enumerate()
                        .filter_map(|(i, byte)| match *byte == 10u8 {
                            true => Some(i),
                            false => None,
                        })
                        .collect();

                    match 2 <= newline_indices.len() {
                        true => {
                            let second_newline_index = *newline_indices.get(1).unwrap();
                            let pws = &buffer[..second_newline_index + 1];
                            let pw_len = pws.len() / 2;
                            match &pws[..pw_len] == &pws[pw_len..] {
                                true => (&pws[..pw_len])
                                    .into_iter()
                                    .copied()
                                    .filter(|byte| *byte != 10u8)
                                    .collect::<Vec<_>>()
                                    .into(),
                                false => csync_err!(PasswordConfirmationFail)?,
                            }
                        }
                        false => csync_err!(PasswordConfirmationFail)?,
                    }
                }
                false => buffer.into_iter().take_while(|byte| *byte != 10u8).collect::<Vec<_>>().into(),
            }
        }
    });

    match confirm_password && isatty {
        true => {
            let confirm = deterministic_hash(run(true, |k| Some(deterministic_hash(k) == initial)));
            // constant time comparison
            match initial == confirm {
                true => Ok(initial),
                false => csync_err!(PasswordConfirmationFail),
            }
        }
        false => Ok(initial),
    }
}

// TODO refactor
//
// too long
fn run<F>(confirm: bool, key_matches: F) -> SecureBytes
where
    F: Fn(SecureBytes) -> Option<bool>,
{
    let (term_width, term_height) = termion::terminal_size().unwrap();
    let stderr = std::io::stderr().into_raw_mode().unwrap();
    let screen = AlternateScreen::from(stderr);

    CliFrontEnd::new(confirm, term_width, term_height, screen, key_matches).handle_keys()
}

fn draw_border<W>(screen: &mut W, border_l: u16, border_r: u16, border_t: u16, border_b: u16)
where
    W: std::io::Write,
{
    macro_rules! c {
        ( $x:expr, $y:expr, $str:literal, $arg:expr ) => {
            match ($x ^ $y) % 8 {
                0 => color!(Black, $str, $arg),
                1 => color!(Blue, $str, $arg),
                2 => color!(Cyan, $str, $arg),
                3 => color!(Green, $str, $arg),
                4 => color!(Magenta, $str, $arg),
                5 => color!(Red, $str, $arg),
                6 => color!(White, $str, $arg),
                7 => color!(Yellow, $str, $arg),
                _ => todo!(),
            }
        };
    }
    macro_rules! draw {
        ( $x:expr, $y:expr ) => {
            match ($x, $y) {
                (x, y) if x == border_l && y == border_t => write!(screen, "{}", c!(x, y, "{}\u{256D}", goto!(x, y))).unwrap(),
                (x, y) if x == border_r && y == border_t => write!(screen, "{}", c!(x, y, "{}\u{256E}", goto!(x, y))).unwrap(),
                (x, y) if x == border_l && y == border_b => write!(screen, "{}", c!(x, y, "{}\u{2570}", goto!(x, y))).unwrap(),
                (x, y) if x == border_r && y == border_b => write!(screen, "{}", c!(x, y, "{}\u{256F}", goto!(x, y))).unwrap(),
                (x, y) if x == border_l || x == border_r => write!(screen, "{}", c!(x, y, "{}|", goto!(x, y))).unwrap(),
                (x, y) if y == border_t || y == border_b => write!(screen, "{}", c!(x, y, "{}-", goto!(x, y))).unwrap(),
                _ => (),
            }
        };
    }

    for x in border_l..border_r + 1 {
        draw!(x, border_t);
        draw!(x, border_b);
    }
    for y in border_t..border_b + 1 {
        draw!(border_l, y);
        draw!(border_r, y);
    }
}
