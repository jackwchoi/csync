use crate::secure_vec::*;
use std::io::{stderr, stdin, Write};
use termion::{color, cursor, event::Key, input::TermRead, raw::IntoRawMode, screen::AlternateScreen};

macro_rules! color {
    ( $color:ident, $fmt_str:literal $( , $arg:expr )* ) => {
        format!("{}{}{}", color::Fg(color::$color), format!($fmt_str $( , $arg )*), color::Fg(color::Reset))
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


// TODO refactor
//
// too long
pub fn run<F>(confirm: bool, key_matches: F) -> SecureBytes
where
    F: Fn(SecureBytes) -> Option<bool>,
{
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

    const CONFIRM_HEADER: &str = "Confirm your password: ";
    const ENTER_HEADER: &str = "Enter your password: ";
    const LENGTH_HEADER: &str = "Length: ";
    const STRENGTH_HEADER: &str = "Strength: ";
    const SUGGESTION_HEADER: &str = "Suggestion: ";
    const WARNING_HEADER: &str = "Warning: ";

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
        ( $cache:ident, $fmt_str:literal $( , $arg:expr )* ) => {
            cached_write!($cache, {true}, {}, $fmt_str $( , $arg )*)
        };
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
