use std::io;

pub fn device_name(value: &str) -> io::Result<&str> {
    let name = value.trim();
    if name.is_empty() || name.chars().count() > 80 || value.chars().any(char::is_control) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Device names must contain 1 to 80 characters and cannot contain control characters.",
        ));
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims_names_and_counts_unicode_characters() {
        assert_eq!(device_name("  Office Mac  ").unwrap(), "Office Mac");
        assert!(device_name(&"🐕".repeat(80)).is_ok());
        for value in ["", " ", "\tMac", "Mac\nMini", &"🐕".repeat(81)] {
            assert!(device_name(value).is_err());
        }
    }
}
