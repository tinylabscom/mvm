//! Fuzz placeholder position classification and position-specific encodings.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mvm_contract::ir::{AuthType, InjectionMode};
use mvm_contract::substitution::{
    PreparedRequest, ProxyRequest, SECRET_PLACEHOLDER_PREFIX, SubstitutionDriver,
    basic_credential, basic_header, locate_placeholders, percent_encode, prepare_request,
};

const PLACEHOLDER: &str = "mvm-secret-f00dbabe";
const SECRET: &str = "fuzz-secret-never-log";

struct Driver {
    mode: InjectionMode,
}

impl SubstitutionDriver for Driver {
    type Error = &'static str;

    fn auth_type(&self, placeholder: &str) -> Option<AuthType> {
        (placeholder == PLACEHOLDER).then_some(if self.mode == InjectionMode::BasicAuth {
            AuthType::Basic
        } else {
            AuthType::Bearer
        })
    }

    fn inject_mode(&self, placeholder: &str) -> Option<InjectionMode> {
        (placeholder == PLACEHOLDER).then_some(self.mode)
    }

    fn substitute(
        &self,
        placeholder: &str,
        _destination: &str,
        text: &str,
    ) -> Result<String, Self::Error> {
        if placeholder != PLACEHOLDER {
            return Err("unknown placeholder");
        }
        Ok(text.replace(placeholder, SECRET))
    }

    fn sign(
        &self,
        _placeholder: &str,
        _destination: &str,
        _method: &str,
        _url: &str,
        _headers: &[(String, String)],
        _body: &[u8],
    ) -> Result<Vec<(String, String)>, Self::Error> {
        Err("not a signing credential")
    }
}

fn mode(index: u8) -> InjectionMode {
    match index % 4 {
        0 => InjectionMode::Header,
        1 => InjectionMode::QueryParam,
        2 => InjectionMode::UrlPath,
        3 => InjectionMode::BasicAuth,
        _ => unreachable!(),
    }
}

fn request(position: u8, fuzz: &str, repeated: bool) -> ProxyRequest {
    let value = if repeated {
        format!("{fuzz}{PLACEHOLDER}:{PLACEHOLDER}")
    } else {
        format!("{fuzz}{PLACEHOLDER}")
    };
    let (url, headers) = match position % 4 {
        0 => (
            "https://api.example.com/v1".to_string(),
            vec![("X-Fuzz".to_string(), value)],
        ),
        1 => (
            format!("https://api.example.com/v1?key={value}"),
            Vec::new(),
        ),
        2 => (
            format!("https://api.example.com/{value}/v1"),
            Vec::new(),
        ),
        3 => (
            "https://api.example.com/v1".to_string(),
            vec![("Authorization".to_string(), basic_header(&value))],
        ),
        _ => unreachable!(),
    };
    ProxyRequest {
        method: "GET".to_string(),
        url,
        headers,
        body: Vec::new(),
    }
}

fn assert_no_placeholder(prepared: &PreparedRequest) {
    assert!(!prepared.url.contains(PLACEHOLDER));
    assert!(
        prepared
            .headers
            .iter()
            .all(|(name, value)| !name.contains(PLACEHOLDER) && !value.contains(PLACEHOLDER))
    );
}

fuzz_target!(|data: &[u8]| {
    let (url_bytes, value_bytes) = data.split_at(data.len() / 2);
    let url = String::from_utf8_lossy(url_bytes);
    let value = String::from_utf8_lossy(value_bytes);
    let headers = vec![
        ("X-Fuzz".to_string(), value.to_string()),
        ("Authorization".to_string(), basic_header(&value)),
    ];

    let first = locate_placeholders(&url, &headers);
    let second = locate_placeholders(&url, &headers);
    assert_eq!(first, second, "classification must be deterministic");
    for located in first {
        assert!(located.placeholder.starts_with(SECRET_PLACEHOLDER_PREFIX));
    }

    let encoded = basic_header(&value);
    assert_eq!(basic_credential("authorization", &encoded).as_deref(), Some(value.as_ref()));
    let escaped = percent_encode(&value);
    assert!(!escaped.bytes().any(|byte| byte.is_ascii_whitespace()));

    let selector = data.first().copied().unwrap_or_default();
    let declared = mode(selector);
    let actual = if selector & 0x10 == 0 {
        selector % 4
    } else {
        selector.wrapping_add(1) % 4
    };
    let driver = Driver { mode: declared };
    match prepare_request(
        &driver,
        "api.example.com",
        request(actual, &value, selector & 0x20 != 0),
    ) {
        Ok(prepared) => assert_no_placeholder(&prepared),
        Err(error) => {
            // A refusal must not reveal a secret obtained during substitution.
            assert!(!error.to_string().contains(SECRET));
        }
    }
});
