//! PEP 508 environment markers, evaluated for one pack target.
//!
//! Only variables whose value the target fixes are accepted. A pack is built
//! once for a known OS, architecture and CPython minor, so `sys_platform` or
//! `python_version` have one answer; `platform_release`, `platform_version`
//! or `extra` do not, and a marker that names one is refused rather than
//! guessed. The patch release of the interpreter is not pinned by the pack
//! (nixpkgs moves it), so a marker over `python_full_version` or
//! `implementation_version` is evaluated at the lowest and a very high patch
//! and accepted only when both agree.

use super::version::{Operator, Specifier, Version};

/// A patch number no CPython release will reach, standing in for "whatever
/// patch the pinned nixpkgs ships".
const HIGH_PATCH: u64 = u32::MAX as u64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MarkerError {
    Syntax(String),
    UnsupportedVariable(String),
    UndefinedComparison(String),
    PatchDependent,
}

impl std::fmt::Display for MarkerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Syntax(detail) => write!(f, "cannot parse it: {detail}"),
            Self::UnsupportedVariable(name) => write!(
                f,
                "it reads `{name}`, which a pack target does not determine"
            ),
            Self::UndefinedComparison(detail) => write!(f, "it compares {detail}"),
            Self::PatchDependent => f.write_str(
                "its outcome depends on the interpreter's patch release, which the pack does not pin",
            ),
        }
    }
}

/// The environment a marker is evaluated in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MarkerTarget {
    pub python_minor: u32,
    pub machine: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Variable {
    SysPlatform,
    PlatformSystem,
    OsName,
    PlatformMachine,
    ImplementationName,
    PlatformPythonImplementation,
    PythonVersion,
    PythonFullVersion,
    ImplementationVersion,
}

impl Variable {
    fn named(name: &str) -> Result<Self, MarkerError> {
        Ok(match name {
            "sys_platform" => Self::SysPlatform,
            "platform_system" => Self::PlatformSystem,
            "os_name" => Self::OsName,
            "platform_machine" => Self::PlatformMachine,
            "implementation_name" => Self::ImplementationName,
            "platform_python_implementation" => Self::PlatformPythonImplementation,
            "python_version" => Self::PythonVersion,
            "python_full_version" => Self::PythonFullVersion,
            "implementation_version" => Self::ImplementationVersion,
            other => return Err(MarkerError::UnsupportedVariable(other.to_string())),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Operand {
    Variable(Variable),
    Literal(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Comparison {
    Version(Operator),
    In,
    NotIn,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Marker {
    Compare {
        lhs: Operand,
        comparison: Comparison,
        rhs: Operand,
    },
    And(Box<Marker>, Box<Marker>),
    Or(Box<Marker>, Box<Marker>),
}

/// Evaluate `text` for `target`, refusing a marker whose answer the target
/// does not fix.
pub(crate) fn evaluate(text: &str, target: MarkerTarget) -> Result<bool, MarkerError> {
    let marker = parse(text)?;
    let low = marker.eval(&Environment::new(target, 0))?;
    let high = marker.eval(&Environment::new(target, HIGH_PATCH))?;
    if low != high {
        return Err(MarkerError::PatchDependent);
    }
    Ok(low)
}

struct Environment {
    machine: &'static str,
    python_version: String,
    full_version: String,
}

impl Environment {
    fn new(target: MarkerTarget, patch: u64) -> Self {
        Self {
            machine: target.machine,
            python_version: format!("3.{}", target.python_minor),
            full_version: format!("3.{}.{patch}", target.python_minor),
        }
    }

    fn value(&self, variable: Variable) -> &str {
        match variable {
            Variable::SysPlatform => "linux",
            Variable::PlatformSystem => "Linux",
            Variable::OsName => "posix",
            Variable::PlatformMachine => self.machine,
            Variable::ImplementationName => "cpython",
            Variable::PlatformPythonImplementation => "CPython",
            Variable::PythonVersion => &self.python_version,
            Variable::PythonFullVersion | Variable::ImplementationVersion => &self.full_version,
        }
    }
}

impl Marker {
    fn eval(&self, env: &Environment) -> Result<bool, MarkerError> {
        match self {
            Self::And(left, right) => Ok(left.eval(env)? && right.eval(env)?),
            Self::Or(left, right) => Ok(left.eval(env)? || right.eval(env)?),
            Self::Compare {
                lhs,
                comparison,
                rhs,
            } => compare(resolve(lhs, env), *comparison, resolve(rhs, env)),
        }
    }
}

fn resolve<'a>(operand: &'a Operand, env: &'a Environment) -> &'a str {
    match operand {
        Operand::Variable(variable) => env.value(*variable),
        Operand::Literal(text) => text,
    }
}

/// The PEP 508 rule: a comparison is a version comparison when the right
/// side forms a valid specifier with the operator and the left side is a
/// version; otherwise it is a string comparison, which `~=` and `===` do not
/// have.
fn compare(lhs: &str, comparison: Comparison, rhs: &str) -> Result<bool, MarkerError> {
    let operator = match comparison {
        Comparison::In => return Ok(rhs.contains(lhs)),
        Comparison::NotIn => return Ok(!rhs.contains(lhs)),
        Comparison::Version(operator) => operator,
    };
    if let (Some(specifier), Some(version)) = (Specifier::new(operator, rhs), Version::parse(lhs)) {
        return Ok(specifier.contains(&version));
    }
    match operator {
        Operator::Equal => Ok(lhs == rhs),
        Operator::NotEqual => Ok(lhs != rhs),
        Operator::Less => Ok(lhs < rhs),
        Operator::LessEqual => Ok(lhs <= rhs),
        Operator::Greater => Ok(lhs > rhs),
        Operator::GreaterEqual => Ok(lhs >= rhs),
        Operator::Compatible | Operator::Arbitrary => Err(MarkerError::UndefinedComparison(
            format!("{lhs:?} and {rhs:?} with an operator that has no string meaning"),
        )),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Lexeme {
    Open,
    Close,
    And,
    Or,
    Not,
    In,
    Operator(Operator),
    Name(String),
    Literal(String),
}

fn tokenize(text: &str) -> Result<Vec<Lexeme>, MarkerError> {
    let mut tokens = Vec::new();
    let mut rest = text;
    loop {
        rest = rest.trim_start();
        let Some(first) = rest.chars().next() else {
            return Ok(tokens);
        };
        let (token, len) = match first {
            '(' => (Lexeme::Open, 1),
            ')' => (Lexeme::Close, 1),
            '\'' | '"' => {
                let end = rest[1..]
                    .find(first)
                    .ok_or_else(|| MarkerError::Syntax("unterminated string".to_string()))?;
                (Lexeme::Literal(rest[1..=end].to_string()), end + 2)
            }
            c if c.is_ascii_alphanumeric() || c == '_' => {
                let len = rest
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
                    .unwrap_or(rest.len());
                let word = &rest[..len];
                let token = match word {
                    "and" => Lexeme::And,
                    "or" => Lexeme::Or,
                    "not" => Lexeme::Not,
                    "in" => Lexeme::In,
                    name => Lexeme::Name(name.to_string()),
                };
                (token, len)
            }
            _ => {
                let (operator, after) = Operator::split(rest)
                    .ok_or_else(|| MarkerError::Syntax(format!("unexpected {first:?}")))?;
                (Lexeme::Operator(operator), rest.len() - after.len())
            }
        };
        tokens.push(token);
        rest = &rest[len..];
    }
}

fn parse(text: &str) -> Result<Marker, MarkerError> {
    let tokens = tokenize(text)?;
    let mut parser = Parser {
        tokens: &tokens,
        position: 0,
    };
    let marker = parser.or()?;
    if parser.position != tokens.len() {
        return Err(MarkerError::Syntax(
            "unexpected text after the marker".to_string(),
        ));
    }
    Ok(marker)
}

struct Parser<'a> {
    tokens: &'a [Lexeme],
    position: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Lexeme> {
        self.tokens.get(self.position)
    }

    fn advance(&mut self) -> Option<&Lexeme> {
        let token = self.tokens.get(self.position);
        self.position += 1;
        token
    }

    fn or(&mut self) -> Result<Marker, MarkerError> {
        let mut marker = self.and()?;
        while self.peek() == Some(&Lexeme::Or) {
            self.position += 1;
            marker = Marker::Or(Box::new(marker), Box::new(self.and()?));
        }
        Ok(marker)
    }

    fn and(&mut self) -> Result<Marker, MarkerError> {
        let mut marker = self.atom()?;
        while self.peek() == Some(&Lexeme::And) {
            self.position += 1;
            marker = Marker::And(Box::new(marker), Box::new(self.atom()?));
        }
        Ok(marker)
    }

    fn atom(&mut self) -> Result<Marker, MarkerError> {
        if self.peek() == Some(&Lexeme::Open) {
            self.position += 1;
            let marker = self.or()?;
            if self.advance() != Some(&Lexeme::Close) {
                return Err(MarkerError::Syntax("unbalanced parenthesis".to_string()));
            }
            return Ok(marker);
        }
        let lhs = self.operand()?;
        let comparison = self.comparison()?;
        let rhs = self.operand()?;
        Ok(Marker::Compare {
            lhs,
            comparison,
            rhs,
        })
    }

    fn operand(&mut self) -> Result<Operand, MarkerError> {
        match self.advance() {
            Some(Lexeme::Name(name)) => Variable::named(name).map(Operand::Variable),
            Some(Lexeme::Literal(text)) => Ok(Operand::Literal(text.clone())),
            other => Err(MarkerError::Syntax(format!(
                "expected a variable or a quoted string, found {other:?}"
            ))),
        }
    }

    fn comparison(&mut self) -> Result<Comparison, MarkerError> {
        let comparison = match self.advance().cloned() {
            Some(Lexeme::Operator(operator)) => Some(Comparison::Version(operator)),
            Some(Lexeme::In) => Some(Comparison::In),
            Some(Lexeme::Not) => (self.advance() == Some(&Lexeme::In)).then_some(Comparison::NotIn),
            _ => None,
        };
        comparison.ok_or_else(|| MarkerError::Syntax("expected a comparison operator".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const X86: MarkerTarget = MarkerTarget {
        python_minor: 12,
        machine: "x86_64",
    };
    const ARM: MarkerTarget = MarkerTarget {
        python_minor: 12,
        machine: "aarch64",
    };

    fn holds(text: &str) -> bool {
        evaluate(text, X86).unwrap_or_else(|e| panic!("{text}: {e}"))
    }

    #[test]
    fn platform_variables_have_the_targets_values() {
        assert!(holds("sys_platform == 'linux'"));
        assert!(!holds("sys_platform == 'win32'"));
        assert!(holds("platform_system == \"Linux\""));
        assert!(holds("os_name == 'posix'"));
        assert!(holds("implementation_name == 'cpython'"));
        assert!(holds("platform_python_implementation != 'PyPy'"));
        assert!(holds("platform_machine == 'x86_64'"));
        assert!(!evaluate("platform_machine == 'x86_64'", ARM).unwrap());
        assert!(evaluate("platform_machine == 'aarch64'", ARM).unwrap());
    }

    #[test]
    fn version_operators_compare_as_versions() {
        assert!(holds("python_version == '3.12'"));
        assert!(holds("python_version != '3.11'"));
        assert!(holds("python_version < '3.13'"));
        assert!(holds("python_version <= '3.12'"));
        assert!(
            holds("python_version > '3.9'"),
            "3.12 > 3.9 as versions, not strings"
        );
        assert!(holds("python_version >= '3.12'"));
        assert!(holds("python_version ~= '3.10'"));
        assert!(holds("python_version === '3.12'"));
        assert!(holds("python_version == '3.*'"));
        assert!(!holds("python_version != '3.12.*'"));
    }

    #[test]
    fn containment_and_reversed_operands() {
        assert!(holds("'linux' in sys_platform"));
        assert!(holds("sys_platform in 'linux darwin'"));
        assert!(holds("'win' not in sys_platform"));
        assert!(holds("platform_machine not in 'arm64 aarch64'"));
        assert!(holds("'3.13' > python_version"));
    }

    #[test]
    fn and_binds_tighter_than_or_and_parentheses_regroup() {
        assert!(holds(
            "sys_platform == 'win32' and python_version < '3.10' or os_name == 'posix'"
        ));
        assert!(!holds(
            "sys_platform == 'win32' and (python_version < '3.10' or os_name == 'posix')"
        ));
        assert!(holds("((sys_platform == 'linux'))"));
    }

    #[test]
    fn a_full_version_marker_is_used_only_when_every_patch_agrees() {
        assert!(holds("python_full_version >= '3.12'"));
        assert!(holds("python_full_version < '3.13'"));
        assert!(!holds("python_full_version < '3.12'"));
        assert!(holds("implementation_version >= '3.10.2'"));
        for text in [
            "python_full_version >= '3.12.4'",
            "python_full_version == '3.12.0'",
            "implementation_version < '3.12.8'",
        ] {
            assert_eq!(
                evaluate(text, X86),
                Err(MarkerError::PatchDependent),
                "{text}"
            );
        }
    }

    #[test]
    fn variables_the_target_does_not_fix_are_refused() {
        for name in [
            "platform_release",
            "platform_version",
            "extra",
            "dependency_groups",
        ] {
            assert_eq!(
                evaluate(&format!("{name} == 'x'"), X86),
                Err(MarkerError::UnsupportedVariable(name.to_string()))
            );
        }
    }

    #[test]
    fn string_comparisons_without_a_string_meaning_are_refused() {
        assert!(matches!(
            evaluate("sys_platform ~= 'linux'", X86),
            Err(MarkerError::UndefinedComparison(_))
        ));
    }

    #[test]
    fn malformed_markers_are_refused() {
        for text in [
            "",
            "sys_platform",
            "sys_platform == ",
            "(sys_platform == 'linux'",
            "sys_platform == 'linux')",
            "sys_platform = 'linux'",
            "sys_platform == 'linux",
            "sys_platform == 'linux' and",
            "sys_platform not 'linux'",
        ] {
            assert!(
                matches!(evaluate(text, X86), Err(MarkerError::Syntax(_))),
                "{text:?}"
            );
        }
    }
}
