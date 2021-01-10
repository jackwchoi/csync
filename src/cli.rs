use crate::secure_vec::*;
use std::io::{stderr, stdin, Write};
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
    F: Fn(SecureBytes) -> bool,
{
    border_b: u16,
    border_l: u16,
    border_r: u16,
    border_t: u16,
    cache_clean: String,
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
    term_width: u16,
    warning_goto: cursor::Goto,
}

impl<W, F> CliFrontEnd<W, F>
where
    W: std::io::Write,
    F: Fn(SecureBytes) -> bool,
{

    fn new(confirm: bool, term_width: u16, term_height: u16, screen: W, key_matches: F) -> Self {
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
            border_b,
            border_l,
            border_r,
            border_t,
            cache_clean: String::new(),
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
            term_width,
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
        if 5 <= self.term_height {
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
                &mut self.cache_strength,
                Yellow,
                self.sugg_goto,
                SUGGESTION_HEADER,
                sugg,
            );
            Self::cached_write_color(
                &mut self.screen,
                &mut self.cache_strength,
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
        Some((self.key_matches)(
            self.chars.iter().copied().collect::<String>().as_bytes().to_vec().into(),
        ))
    }

    fn color_match(&mut self) {
        let new_matches = self.matches();
        match self.cache_is_match == new_matches {
            true => (),
            false => {
                self.cache_is_match = new_matches;
                match new_matches {
                    Some(true) => Self::rewrite_prompt(
                        &mut self.screen,
                        &self.chars,
                        Green,
                        self.confirm,
                        Self::mask_char(true),
                        self.prompt_goto,
                        self.pw_portion_width,
                    ),
                    Some(false) => Self::rewrite_prompt(
                        &mut self.screen,
                        &self.chars,
                        Red,
                        self.confirm,
                        Self::mask_char(false),
                        self.prompt_goto,
                        self.pw_portion_width,
                    ),
                    None => Self::rewrite_prompt(
                        &mut self.screen,
                        &self.chars,
                        Reset,
                        self.confirm,
                        Self::mask_char(true),
                        self.prompt_goto,
                        self.pw_portion_width,
                    ),
                }
            }
        }
    }

    fn run(mut self) -> SecureBytes {
        for key_down in stdin().keys() {
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
                            self.screen,
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
                            self.screen,
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

// TODO refactor
//
// too long
pub fn run<F>(confirm: bool, key_matches: F) -> SecureBytes
where
    F: Fn(SecureBytes) -> Option<bool>,
{
    if !isatty::stderr_isatty() {
        todo!();
    }

    // console has a way to see if stderr is attended
    // use that as the main gateway or tty

    let (term_width, term_height) = termion::terminal_size().unwrap();

    let border_l = proportion!(0.05, term_width);
    let border_r = proportion!(0.95, term_width);
    let border_t = proportion!(0.05, term_height);
    let border_b = proportion!(0.95, term_height);

    let stderr = stderr().into_raw_mode().unwrap();

    let mut screen = AlternateScreen::from(stderr);

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

    let mut chars = Vec::with_capacity(1024);

    let goto_backspace = |chars: &mut Vec<char>| match chars.len() {
        0 => None,
        len if len <= pw_portion_width as usize => Some(goto!(prompt_x + enter_message_len + len as u16, prompt_y)),
        _ => None,
    };
    //
    let goto_asterisk = |chars: &mut Vec<char>| match chars.len() {
        len if len < pw_portion_width as usize => Some(goto!(prompt_x + enter_message_len + len as u16, prompt_y)),
        _ => None,
    };

    // TODO refactor later
    let score = |chars: &mut Vec<char>| zxcvbn::zxcvbn(&chars.iter().collect::<String>(), &[]).unwrap().score();

    // cache
    macro_rules! cached_write {
        ( $cache:ident, $cache_check:block, $if_stale:block, $fmt_str:literal $( , $arg:expr )* ) => {{
            let content = format!("{}", format!($fmt_str, $( $arg ),*));
            if $cache != content && $cache_check {
                $cache = content;
                write!(screen, "{}", $cache).unwrap();
                $if_stale;
            }
        }};
        ( $cache:ident, $color:ident, $goto:expr, $header:expr, $desc:expr ) => {{
            let uncolored_content = format!("{}{:>23}{}", $goto, $header, $desc);
            if $cache != uncolored_content {

                clean!($goto, $cache);

                $cache = uncolored_content;
                let colored_content = color!($color, "{}", $cache);
                write!(screen, "{}", colored_content).unwrap();
            }
        }}
    }

    let mut cache_clean = String::new();
    macro_rules! clean {
        ( $goto:expr, $content_cache:ident ) => {
            cached_write!(
                cache_clean,
                { 0 < $content_cache.len() },
                { $content_cache.clear() },
                "{}{}",
                $goto,
                (0..$content_cache.len()).map(|_| ' ').collect::<String>()
            )
        };
    }

    let mut cache_length = String::new();
    let mut cache_strength = String::new();
    let mut cache_suggestion = String::new();
    let mut cache_warning = String::new();
    macro_rules! diag {
        () => {
            if 5 <= term_height {
                //clean!(pw_len_goto, cache_length);
                cached_write!(cache_length, Reset, pw_len_goto, LENGTH_HEADER, chars.len());

                if 0 < chars.len() {
                    // write strength
                    //clean!(score_goto, cache_strength);
                    let desc = match score(&mut chars) {
                        0 => color!(Red, "SUX"),
                        1 => color!(Red, "VERY BAD"),
                        2 => color!(Yellow, "BAD"),
                        3 => color!(Reset, "GOOD"),
                        4 => color!(Green, "EXCELLENT"),
                        _ => unreachable!(),
                    };
                    cached_write!(cache_strength, Reset, score_goto, STRENGTH_HEADER, desc);

                    // write suggestions
                    //clean!(sugg_goto, cache_suggestion);
                    //clean!(warning_goto, cache_warning);
                    let (sugg, warning) = match zxcvbn::zxcvbn(&chars.iter().collect::<String>(), &[])
                        .unwrap()
                        .feedback()
                    {
                        Some(sugg) => (
                            format!("{}", sugg.suggestions()[0]),
                            match sugg.warning() {
                                Some(warning) => format!("{}", warning),
                                None => String::new(),
                            },
                        ),
                        None => (String::new(), String::new()),
                    };
                    cached_write!(cache_suggestion, Yellow, sugg_goto, SUGGESTION_HEADER, sugg);
                    cached_write!(cache_warning, Yellow, warning_goto, WARNING_HEADER, warning);
                }
            }
        };
    }

    if 7 <= term_height {
        draw_border(&mut screen, border_l, border_r, border_t, border_b);
    }

    let mask_char = |matches| match matches {
        true => '\u{2713}',
        false => '\u{10102}',
    };
    macro_rules! rewrite_prompt {
        ( $color:ident, $mask:expr ) => {
            write!(
                screen,
                "{}{}",
                prompt_goto,
                color!(
                    $color,
                    "{}{}",
                    format!(
                        "{:>23}{}{}",
                        match confirm {
                            true => CONFIRM_HEADER,
                            false => ENTER_HEADER,
                        },
                        (0..chars.len()).map(|_| $mask).collect::<String>(),
                        (chars.len()..pw_portion_width as usize)
                            .map(|_| '_')
                            .collect::<String>()
                    ),
                    left!(pw_portion_width)
                )
            )
            .unwrap()
        };
    }
    rewrite_prompt!(Reset, mask_char(true));

    let mut is_match = None;

    macro_rules! matches {
        () => {
            key_matches(chars.iter().copied().collect::<String>().as_bytes().to_vec().into())
        };
    }
    macro_rules! color_match {
        (  ) => {{
            let new_matches = matches!();
            match is_match == new_matches {
                true => (),
                false => {
                    is_match = new_matches;
                    match new_matches {
                        Some(true) => rewrite_prompt!(Green, mask_char(true)),
                        Some(false) => rewrite_prompt!(Red, mask_char(false)),
                        None => rewrite_prompt!(Reset, mask_char(true)),
                    }
                }
            }
        }};
    }
    for key_down in stdin().keys() {
        //
        match key_down.unwrap() {
            //
            Key::Char('\n') => break,
            //
            Key::Ctrl('c') => panic!(),

            //
            Key::Backspace if 0 < chars.len() => {
                if let Some(goto) = goto_backspace(&mut chars) {
                    write!(
                        screen,
                        "{}{}{}{}",
                        goto,
                        left!(1),
                        match is_match {
                            Some(true) => color!(Green, "_"),
                            Some(false) => color!(Red, "_"),
                            None => color!(Reset, "_"),
                        },
                        left!(1)
                    )
                    .unwrap();
                }
                chars.pop().unwrap();
                diag!();
                color_match!();
            }
            //
            Key::Char(chr) => {
                if let Some(goto) = goto_asterisk(&mut chars) {
                    write!(
                        screen,
                        "{}{}",
                        goto,
                        match is_match {
                            Some(true) => color!(Green, "{}", mask_char(true)),
                            Some(false) => color!(Red, "{}", mask_char(false)),
                            None => color!(Reset, "{}", mask_char(true)),
                        },
                    )
                    .unwrap();
                }
                chars.push(chr);
                diag!();
                color_match!();
            }
            //
            _ => (),
        }
    }

    screen.flush().unwrap();

    chars.into_iter().collect::<String>().as_bytes().to_vec().into()
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
