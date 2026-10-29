//! Read this process's loaded entitlements through public Security.framework
//! APIs. Inspecting a replacement file on disk cannot establish these values.

use core_foundation::base::{CFAllocatorRef, CFType, CFTypeRef, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::error::CFErrorRef;
use core_foundation::string::{CFString, CFStringRef};
use std::ffi::c_void;

// These two public macOS APIs are declared in Security.framework/Headers/SecTask.h.
// The existing security-framework Rust wrapper does not expose them.
// https://developer.apple.com/documentation/security/sectaskcreatefromself(_:)
// https://developer.apple.com/documentation/security/sectaskcopyvalueforentitlement(_:_:_:)
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecTaskCreateFromSelf(allocator: CFAllocatorRef) -> *mut c_void;
    fn SecTaskCopyValueForEntitlement(
        task: *mut c_void,
        entitlement: CFStringRef,
        error: *mut CFErrorRef,
    ) -> CFTypeRef;
}

fn is_true(value: &CFType) -> bool {
    value.downcast::<CFBoolean>().is_some_and(bool::from)
}

pub(super) fn require_true(keys: &[&str]) -> Result<(), String> {
    // SAFETY: null selects the default allocator. The public API returns
    // either null or a retained SecTask CF object representing this process.
    let raw = unsafe { SecTaskCreateFromSelf(std::ptr::null()) };
    if raw.is_null() {
        return Err("cannot inspect loaded process entitlements".into());
    }
    // SAFETY: raw is a non-null CF object owned under the Create rule.
    // CFType releases it on every exit, including an entitlement refusal.
    let task = unsafe { CFType::wrap_under_create_rule(raw.cast_const()) };
    for name in keys {
        let key = CFString::new(name);
        // SAFETY: task and key remain live across the call. A null error-output
        // pointer is explicitly supported; null values are always refused.
        let raw_value = unsafe {
            SecTaskCopyValueForEntitlement(
                task.as_CFTypeRef().cast_mut(),
                key.as_concrete_TypeRef(),
                std::ptr::null_mut(),
            )
        };
        if raw_value.is_null() {
            return Err(format!("loaded process entitlement {name} is unavailable"));
        }
        // SAFETY: the non-null return is a retained CF object under the Copy
        // rule. Checked downcasting below rejects every non-boolean type.
        let value = unsafe { CFType::wrap_under_create_rule(raw_value) };
        if !is_true(&value) {
            return Err(format!(
                "loaded process entitlement {name} is not boolean true"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_foundation::number::CFNumber;

    #[test]
    fn native_values_require_boolean_true_not_truthy_strings_or_numbers() {
        assert!(is_true(&CFBoolean::true_value().as_CFType()));
        assert!(!is_true(&CFBoolean::false_value().as_CFType()));
        assert!(!is_true(&CFString::new("true").as_CFType()));
        assert!(!is_true(&CFNumber::from(1_i32).as_CFType()));
    }

    #[test]
    fn current_task_refuses_an_absent_entitlement_without_loading_an_executable() {
        let key = "com.mvm.test.nonexistent-loaded-entitlement";
        let error = require_true(&[key]).unwrap_err();
        assert!(error.contains(key), "{error}");
    }
}
