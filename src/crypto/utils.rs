use thiserror::Error;

/// Error from the OS random number generator.
#[derive(Debug, Error)]
#[error("{0}")]
pub struct RandomError(&'static str);

/// Fills a buffer with cryptographically secure random bytes from the
/// operating system (`getrandom`, the same source `orion` draws from).
///
/// # Errors
/// - Returns an error if the buffer is empty.
/// - Returns an error if the random number generation fails.
pub fn secure_bytes_fill(buffer: &mut [u8]) -> Result<(), RandomError> {
    if buffer.is_empty() {
        return Err(RandomError("Buffer is empty"));
    }

    getrandom::fill(buffer).map_err(|_| RandomError("Failed to fill buffer with random bytes"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_bytes_fill_fills_buffer_with_random_bytes() {
        let mut buffer = [0u8; 16];
        secure_bytes_fill(&mut buffer).unwrap();
        assert!(buffer.iter().any(|&byte| byte != 0));
    }

    #[test]
    fn secure_bytes_fill_returns_error_for_empty_buffer() {
        let mut buffer: [u8; 0] = [];
        let result = secure_bytes_fill(&mut buffer);
        assert!(result.is_err());
    }
}
