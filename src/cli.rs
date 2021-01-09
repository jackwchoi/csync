use crate::secure_vec::*;
use std::io::{stderr, stdin, Write};
use termion::{cursor, event::Key, input::TermRead, raw::IntoRawMode, screen::AlternateScreen};

macro_rules! color {
    ( $color:ident, $fmt_str:literal $( , $arg:expr )* ) => {
        ansi_term::Colour::$color.paint(format!($fmt_str $( , $arg )*))
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

macro_rules! write_color {
    ( $screen:expr, $color:ident, $goto:expr, $header:expr $( , $arg:expr )+ ) => {
        write!(
            $screen,
            "{}",
            color!($color, "{}{:>23}{}", $goto, $header $( , $arg )+ )
        )
        .unwrap()
    }
}

macro_rules! proportion {
    ( $frac:literal, $value:expr ) => {
        ($frac * $value as f64).round() as u16
    };
}

pub fn run(confirm: bool) -> SecureBytes {
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
        ( $cache:ident, $fmt_str:literal $( , $arg:expr )* ) => {{
            let content = format!($fmt_str, $( $arg ),*);
            if $cache != content {
                $cache = content;
                write_color!(screen, White, $cache, "", "");
            }
        }};
    }

    let mut cache_clean = String::new();
    macro_rules! clean {
        ( $goto:expr ) => {{
            cached_write!(
                cache_clean,
                "{}{}",
                $goto,
                (0..pw_portion_width + enter_message_len)
                    .map(|_| ' ')
                    .collect::<String>()
            );
        }};
    }

    let mut cache_strength = String::new();
    macro_rules! diag {
        () => {
            clean!(pw_len_goto);
            write_color!(screen, White, pw_len_goto, LENGTH_HEADER, chars.len());

            if 0 < chars.len() {
                // write strength
                clean!(score_goto);
                let desc = match score(&mut chars) {
                    0 => color!(Red, "SUX"),
                    1 => color!(Red, "VERY BAD"),
                    2 => color!(Yellow, "BAD"),
                    3 => color!(White, "GOOD"),
                    4 => color!(Green, "EXCELLENT"),
                    _ => unreachable!(),
                };
                write_color!(screen, White, score_goto, STRENGTH_HEADER, desc);

                // write suggestions
                clean!(sugg_goto);
                clean!(warning_goto);
                if let Some(sugg) = zxcvbn::zxcvbn(&chars.iter().collect::<String>(), &[])
                    .unwrap()
                    .feedback()
                {
                    write_color!(screen, Yellow, sugg_goto, SUGGESTION_HEADER, sugg.suggestions()[0]);
                    if let Some(warning) = sugg.warning() {
                        write_color!(screen, Yellow, warning_goto, WARNING_HEADER, warning);
                    }
                }
            }
        };
    }

    if 7 <= term_height {
        draw_border(&mut screen, border_l, border_r, border_t, border_b);
    }

    write!(
        screen,
        "{}{}{}",
        prompt_goto,
        format!(
            "{:>23}{}",
            match confirm {
                true => CONFIRM_HEADER,
                false => ENTER_HEADER,
            },
            (0..pw_portion_width).map(|_| '_').collect::<String>()
        ),
        left!(pw_portion_width)
    )
    .unwrap();
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
                    write!(screen, "{}{}_{}", goto, left!(1), left!(1)).unwrap();
                }
                chars.pop().unwrap();
                if 5 <= term_height {
                    diag!();
                }
            }
            //
            Key::Char(chr) => {
                if let Some(goto) = goto_asterisk(&mut chars) {
                    write!(screen, "{}*", goto).unwrap();
                }
                chars.push(chr);
                if 5 <= term_height {
                    diag!();
                }
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
                1 => color!(Red, $str, $arg),
                2 => color!(Green, $str, $arg),
                3 => color!(Yellow, $str, $arg),
                4 => color!(Blue, $str, $arg),
                5 => color!(Purple, $str, $arg),
                6 => color!(Cyan, $str, $arg),
                7 => color!(White, $str, $arg),
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
