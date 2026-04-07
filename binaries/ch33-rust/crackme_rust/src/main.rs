// ============================================================================
// Reverse Engineering Training — Chapter 33
// crackme_rust: Rust training binary
//
// This crackme illustrates Rust patterns visible in RE:
//   - Option<T> / Result<T, E> and unwrap / match
//   - Enums with data (tagged unions)
//   - Trait objects (dyn Trait) and trait vtables
//   - String / &str handling (fat pointers, no null terminator)
//   - Panics and error messages
//   - Iterators and closures
//
// Usage : ./crackme_rust <username> <serial>
// ============================================================================

use std::env;
use std::fmt;
use std::process;

// ---------------------------------------------------------------------------
// Constants — identifiable with `strings` or in .rodata
// ---------------------------------------------------------------------------
const MAGIC: u32 = 0xDEAD_C0DE;
const VERSION: &str = "RustCrackMe-v3.3";
const SERIAL_PREFIX: &str = "RUST-";
const SERIAL_PARTS: usize = 4;
const SEPARATOR: char = '-';

// ---------------------------------------------------------------------------
// Enum with data — produces a tag + payload in memory (tagged union)
// Recognizable in RE by comparisons on the discriminant
// ---------------------------------------------------------------------------
#[derive(Debug, Clone)]
enum LicenseType {
    Trial { days_left: u32 },
    Standard { seats: u32 },
    Enterprise { seats: u32, support: bool },
}

impl LicenseType {
    /// The exhaustive `match` on this enum generates a jump table
    /// or a cascade of comparisons depending on optimization level.
    fn max_features(&self) -> u32 {
        match self {
            LicenseType::Trial { days_left } => {
                if *days_left > 0 { 5 } else { 0 }
            }
            LicenseType::Standard { seats } => 10 + seats,
            LicenseType::Enterprise { seats, support } => {
                let base = 50 + seats * 2;
                if *support { base + 100 } else { base }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Trait + implementation — the trait object (dyn Validator) uses a fat
// pointer (data_ptr, vtable_ptr) different from C++ vtables
// ---------------------------------------------------------------------------
trait Validator {
    fn name(&self) -> &str;
    fn validate(&self, input: &str) -> Result<(), String>;
}

/// Verifies that the serial starts with the correct prefix
struct PrefixValidator;

impl Validator for PrefixValidator {
    fn name(&self) -> &str {
        "PrefixCheck"
    }

    fn validate(&self, input: &str) -> Result<(), String> {
        if input.starts_with(SERIAL_PREFIX) {
            Ok(())
        } else {
            Err(format!(
                "The serial must start with '{}'",
                SERIAL_PREFIX
            ))
        }
    }
}

/// Verifies the format: RUST-XXXX-XXXX-XXXX (4 groups after the prefix)
struct FormatValidator;

impl Validator for FormatValidator {
    fn name(&self) -> &str {
        "FormatCheck"
    }

    fn validate(&self, input: &str) -> Result<(), String> {
        let body = input.strip_prefix(SERIAL_PREFIX).unwrap_or(input);
        let parts: Vec<&str> = body.split(SEPARATOR).collect();

        if parts.len() != SERIAL_PARTS {
            return Err(format!(
                "Expected {} groups after the prefix, found {}",
                SERIAL_PARTS,
                parts.len()
            ));
        }

        // Each group must be exactly 4 hexadecimal characters
        for (i, part) in parts.iter().enumerate() {
            if part.len() != 4 {
                return Err(format!("Group {}: invalid length ({})", i + 1, part.len()));
            }
            if !part.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(format!("Group {}: non-hexadecimal characters", i + 1));
            }
        }

        Ok(())
    }
}

/// Verifies the mathematical consistency of the serial relative to the username
struct ChecksumValidator {
    expected_checksum: u32,
}

impl ChecksumValidator {
    fn new(username: &str) -> Self {
        // Checksum derivation algorithm from the username
        // In RE, this logic must be reconstructed to write a keygen
        let mut hash: u32 = MAGIC;
        for (i, byte) in username.bytes().enumerate() {
            hash = hash.wrapping_mul(31).wrapping_add(byte as u32);
            hash ^= (i as u32).wrapping_shl(((byte & 0x0F) + 1) as u32);
            hash = hash.rotate_left(7);
        }
        // Final mixing
        hash ^= hash >> 16;
        hash = hash.wrapping_mul(0x45D9_F3B1);
        hash ^= hash >> 13;
        hash = hash.wrapping_mul(0x1DA2_85FC);
        hash ^= hash >> 16;

        Self {
            expected_checksum: hash,
        }
    }
}

impl Validator for ChecksumValidator {
    fn name(&self) -> &str {
        "ChecksumCheck"
    }

    fn validate(&self, input: &str) -> Result<(), String> {
        let body = input
            .strip_prefix(SERIAL_PREFIX)
            .ok_or_else(|| String::from("Missing prefix"))?;

        // Parse the 4 hexadecimal groups into a u128, then extract the low 32 bits
        let combined: Option<u128> = body
            .split(SEPARATOR)
            .map(|part| u32::from_str_radix(part, 16).ok().map(|v| v as u128))
            .try_fold(0u128, |acc, maybe_val| {
                maybe_val.map(|v| (acc << 16) | v)
            });

        match combined {
            Some(value) => {
                let serial_checksum = (value & 0xFFFF_FFFF) as u32;
                if serial_checksum == self.expected_checksum {
                    Ok(())
                } else {
                    Err(format!(
                        "Invalid checksum: expected 0x{:08X}, got 0x{:08X}",
                        self.expected_checksum, serial_checksum
                    ))
                }
            }
            // This None triggers an error path recognizable in RE
            // (comparison of the Option discriminant then branching)
            None => Err(String::from("Unable to parse hexadecimal groups")),
        }
    }
}

// ---------------------------------------------------------------------------
// Struct containing a Vec<Box<dyn Validator>> — dynamic dispatch
// In RE: each call goes through the trait object's vtable pointer
// ---------------------------------------------------------------------------
struct ValidationPipeline {
    validators: Vec<Box<dyn Validator>>,
}

impl ValidationPipeline {
    fn new() -> Self {
        Self {
            validators: Vec::new(),
        }
    }

    fn add(&mut self, v: Box<dyn Validator>) {
        self.validators.push(v);
    }

    /// Executes all validators in sequence.
    /// Uses an iterator + closure — frequent pattern in Rust.
    fn run(&self, serial: &str) -> Result<(), ValidationError> {
        for (idx, validator) in self.validators.iter().enumerate() {
            // Call via the fat pointer (vtable dispatch)
            validator.validate(serial).map_err(|msg| ValidationError {
                step: idx + 1,
                validator_name: validator.name().to_string(),
                message: msg,
            })?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Custom error struct — implements Display and Debug
// Formatted messages end up in the binary's strings
// ---------------------------------------------------------------------------
#[derive(Debug)]
struct ValidationError {
    step: usize,
    validator_name: String,
    message: String,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[Step {}/{}] {} : {}",
            self.step, SERIAL_PARTS, self.validator_name, self.message
        )
    }
}

// ---------------------------------------------------------------------------
// Utility functions — illustrate various Rust patterns
// ---------------------------------------------------------------------------

/// Determines the license type from the first group of the serial.
/// The `match` on a range of values generates bounded comparisons in asm.
fn determine_license(serial: &str) -> Option<LicenseType> {
    let body = serial.strip_prefix(SERIAL_PREFIX)?;
    let first_group = body.split(SEPARATOR).next()?;
    let value = u16::from_str_radix(first_group, 16).ok()?;

    // Pattern matching on ranges — generates cmp/jae/jbe in asm
    let license = match value {
        0x0000..=0x00FF => LicenseType::Trial { days_left: 30 },
        0x0100..=0x0FFF => LicenseType::Standard {
            seats: (value / 256) as u32,
        },
        0x1000..=0xFFFF => LicenseType::Enterprise {
            seats: (value / 512) as u32,
            support: (value & 1) == 1,
        },
    };

    Some(license)
}

/// Displays a banner — &str literals are fat pointers (ptr, len)
fn print_banner() {
    println!("╔══════════════════════════════════════════╗");
    println!("║      {} — Crackme      ║", VERSION);
    println!("║  Reverse Engineering Training (Ch.33)   ║");
    println!("╚══════════════════════════════════════════╝");
    println!();
}

/// Displays usage and exits — process::exit generates a call
/// recognizable (often inlined as syscall exit_group)
fn usage_and_exit() -> ! {
    eprintln!("Usage : crackme_rust <username> <serial>");
    eprintln!("  username : your username (non-empty)");
    eprintln!(
        "  serial   : in the format {0}XXXX{1}XXXX{1}XXXX{1}XXXX",
        SERIAL_PREFIX, SEPARATOR
    );
    process::exit(1);
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
fn main() {
    print_banner();

    // Argument collection — Vec<String> with fat pointers
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        usage_and_exit();
    }

    let username = &args[1];
    let serial = &args[2];

    // Username validation — unwrap_or / is_empty patterns
    if username.is_empty() {
        eprintln!("Error: the username cannot be empty.");
        process::exit(1);
    }

    println!("[*] Username : {}", username);
    println!("[*] Serial   : {}", serial);
    println!();

    // Building the validation pipeline with dynamic dispatch
    let mut pipeline = ValidationPipeline::new();
    pipeline.add(Box::new(PrefixValidator));
    pipeline.add(Box::new(FormatValidator));
    pipeline.add(Box::new(ChecksumValidator::new(username)));

    // Execution — the `match` on Result<(), ValidationError> is the point
    // central point that the RE analyst must identify
    match pipeline.run(serial) {
        Ok(()) => {
            println!("[+] VALID serial!");
            println!();

            // License type determination — Option chain with ?
            match determine_license(serial) {
                Some(license) => {
                    let features = license.max_features();
                    println!("[+] License type: {:?}", license);
                    println!("[+] Unlocked features: {}", features);
                }
                // This None should never happen if the serial is valid
                // but the compiler still generates the code for this arm
                None => {
                    eprintln!("[-] Unable to determine license type.");
                }
            }

            println!();
            println!("Congratulations, you solved the crackme!");
        }
        Err(e) => {
            eprintln!("[-] Validation failed: {}", e);
            println!();
            println!("Hint: analyze the checksum algorithm in ChecksumValidator.");
            process::exit(1);
        }
    }
}
