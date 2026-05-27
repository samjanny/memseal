use rand_core::{OsRng, TryRngCore};

/// Generates a random `usize` within the range `[min, max]` (inclusive).
///
/// # Arguments
/// - `min`: The minimum value of the range (inclusive).
/// - `max`: The maximum value of the range (inclusive).
///
/// # Returns
/// - `Ok(usize)`: A random number within the specified range.
/// - `Err(&'static str)`: An error message if the range is invalid or random generation fails.
///
/// # Errors
/// - Returns an error if `min >= max`.
/// - Returns an error if the random number generation fails.
pub fn secure_usize_between(min: usize, max: usize) -> Result<usize, &'static str> {
    if min >= max {
        return Err("Invalid range: min must be less than max");
    }

    let range = max - min + 1;

    // Calculate the maximum limit to avoid bias
    let limit = usize::MAX - (usize::MAX % range);

    // Rejection sampling
    let rand_val = loop {
        let val = match OsRng.try_next_u64() {
            Ok(v) => v as usize,
            Err(_) => return Err("Failed to generate random number"),
        };

        if val < limit {
            break val;
        }
    };

    Ok(min + (rand_val % range))
}

/// Generates a random `u32` within the range `[min, max]` (inclusive).
///
/// # Arguments
/// - `min`: The minimum value of the range (inclusive).
/// - `max`: The maximum value of the range (inclusive).
///
/// # Returns
/// - `Ok(u32)`: A random number within the specified range.
/// - `Err(&'static str)`: An error message if the range is invalid or random generation fails.
///
/// # Errors
/// - Returns an error if `min >= max`.
/// - Returns an error if the random number generation fails.
pub fn secure_u32_between(min: u32, max: u32) -> Result<u32, &'static str> {
    if min >= max {
        return Err("Invalid range: min must be less than max");
    }

    let range = max - min + 1;

    // Calculate the maximum limit to avoid bias
    let limit = u32::MAX - (u32::MAX % range);

    // Rejection sampling
    let rand_val = loop {
        let val = match OsRng.try_next_u32() {
            Ok(v) => v,
            Err(_) => return Err("Failed to generate random number"),
        };

        if val < limit {
            break val;
        }
    };

    Ok(min + (rand_val % range))
}

/// Generates a random `u64` within the range `[min, max]` (inclusive).
///
/// # Arguments
/// - `min`: The minimum value of the range (inclusive).
/// - `max`: The maximum value of the range (inclusive).
///
/// # Returns
/// - `Ok(u64)`: A random number within the specified range.
/// - `Err(&'static str)`: An error message if the range is invalid or random generation fails.
///
/// # Errors
/// - Returns an error if `min >= max`.
/// - Returns an error if the random number generation fails.
pub fn secure_u64_between(min: u64, max: u64) -> Result<u64, &'static str> {
    if min >= max {
        return Err("Invalid range: min must be less than max");
    }

    let range = max - min + 1;

    // Calculate the maximum limit to avoid bias
    let limit = u64::MAX - (u64::MAX % range);

    // Rejection sampling
    let rand_val = loop {
        let val = match OsRng.try_next_u64() {
            Ok(v) => v,
            Err(_) => return Err("Failed to generate random number"),
        };

        if val < limit {
            break val;
        }
    };

    Ok(min + (rand_val % range))
}

/// Generates a random `i32` within the range `[min, max]` (inclusive).
///
/// # Arguments
/// - `min`: The minimum value of the range (inclusive).
/// - `max`: The maximum value of the range (inclusive).
///
/// # Returns
/// - `Ok(i32)`: A random number within the specified range.
/// - `Err(&'static str)`: An error message if the range is invalid or random generation fails.
///
/// # Errors
/// - Returns an error if `min >= max`.
/// - Returns an error if the random number generation fails.
pub fn secure_i32_between(min: i32, max: i32) -> Result<i32, &'static str> {
    if min >= max {
        return Err("Invalid range: min must be less than max");
    }

    // Use u32 arithmetic to avoid signed overflow when min=i32::MIN, max=i32::MAX
    let range = (max as u32).wrapping_sub(min as u32).wrapping_add(1);

    if range == 0 {
        // Full u32 range — any value is valid, no rejection needed
        let val = OsRng
            .try_next_u32()
            .map_err(|_| "Failed to generate random number")?;
        return Ok(val as i32);
    }

    let limit = u32::MAX - (u32::MAX % range);

    let rand_val = loop {
        let val = match OsRng.try_next_u32() {
            Ok(v) => v,
            Err(_) => return Err("Failed to generate random number"),
        };

        if val < limit {
            break val;
        }
    };

    Ok((min as u32).wrapping_add(rand_val % range) as i32)
}

/// Generates a random `i64` within the range `[min, max]` (inclusive).
///
/// # Arguments
/// - `min`: The minimum value of the range (inclusive).
/// - `max`: The maximum value of the range (inclusive).
///
/// # Returns
/// - `Ok(i64)`: A random number within the specified range.
/// - `Err(&'static str)`: An error message if the range is invalid or random generation fails.
///
/// # Errors
/// - Returns an error if `min >= max`.
/// - Returns an error if the random number generation fails.
pub fn secure_i64_between(min: i64, max: i64) -> Result<i64, &'static str> {
    if min >= max {
        return Err("Invalid range: min must be less than max");
    }

    let range = (max as u64).wrapping_sub(min as u64).wrapping_add(1);

    if range == 0 {
        let val = OsRng
            .try_next_u64()
            .map_err(|_| "Failed to generate random number")?;
        return Ok(val as i64);
    }

    let limit = u64::MAX - (u64::MAX % range);

    let rand_u64 = loop {
        match OsRng.try_next_u64() {
            Ok(val) => {
                if val < limit {
                    break val;
                }
            }
            Err(_) => return Err("Failed to generate random number"),
        };
    };

    Ok((min as u64).wrapping_add(rand_u64 % range) as i64)
}

/// Fills a buffer with cryptographically secure random bytes.
///
/// # Arguments
/// - `buffer`: A mutable slice of bytes to be filled with random data.
///
/// # Returns
/// - `Ok(())`: If the buffer is successfully filled with random bytes.
/// - `Err(&'static str)`: An error message if the buffer is empty or random generation fails.
///
/// # Errors
/// - Returns an error if the buffer is empty.
/// - Returns an error if the random number generation fails.
pub fn secure_bytes_fill(buffer: &mut [u8]) -> Result<(), &'static str> {
    if buffer.is_empty() {
        return Err("Buffer is empty");
    }

    OsRng
        .try_fill_bytes(buffer)
        .map_err(|_| "Failed to fill buffer with random bytes")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_usize_between_returns_value_within_range() {
        let result = secure_usize_between(10, 20).unwrap();
        assert!((10..=20).contains(&result));
    }

    #[test]
    fn secure_usize_between_returns_error_for_invalid_range() {
        let result = secure_usize_between(20, 10);
        assert!(result.is_err());
    }

    #[test]
    fn secure_u32_between_returns_value_within_range() {
        let result = secure_u32_between(100, 200).unwrap();
        assert!((100..=200).contains(&result));
    }

    #[test]
    fn secure_u32_between_returns_error_for_invalid_range() {
        let result = secure_u32_between(200, 100);
        assert!(result.is_err());
    }

    #[test]
    fn secure_u64_between_returns_value_within_range() {
        let result = secure_u64_between(1_000, 2_000).unwrap();
        assert!((1_000..=2_000).contains(&result));
    }

    #[test]
    fn secure_u64_between_returns_error_for_invalid_range() {
        let result = secure_u64_between(2_000, 1_000);
        assert!(result.is_err());
    }

    #[test]
    fn secure_i32_between_returns_value_within_range() {
        let result = secure_i32_between(-50, 50).unwrap();
        assert!((-50..=50).contains(&result));
    }

    #[test]
    fn secure_i32_between_returns_error_for_invalid_range() {
        let result = secure_i32_between(50, -50);
        assert!(result.is_err());
    }

    #[test]
    fn secure_i64_between_returns_value_within_range() {
        let result = secure_i64_between(-1_000, 1_000).unwrap();
        assert!((-1_000..=1_000).contains(&result));
    }

    #[test]
    fn secure_i64_between_returns_error_for_invalid_range() {
        let result = secure_i64_between(1_000, -1_000);
        assert!(result.is_err());
    }

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
