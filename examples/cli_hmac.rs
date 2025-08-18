/// hmac-sha256 command line interface
/// supports computing hmacs for strings and files
use clap::{Parser, Subcommand};
use std::fs::File;
use std::io::{self, BufRead, Read};
use std::path::PathBuf;

// import our implementation
#[path = "hmac_sha256_from_scratch.rs"]
mod hmac_impl;

use hmac_impl::{from_hex, hmac_sha256, to_hex};

#[derive(Parser)]
#[command(
  name = "hmac-sha256",
  about = "A CLI tool for computing HMAC-SHA256",
  version = "0.1.0"
)]
struct Cli {
  #[command(subcommand)]
  command: Commands,

  /// output format (hex, base64, or raw)
  #[arg(short, long, default_value = "hex")]
  format: String,

  /// verify mode - check if computed hmac matches expected value
  #[arg(short, long)]
  verify: Option<String>,

  /// quiet mode - only output the hmac or verification result
  #[arg(short, long)]
  quiet: bool,
}

#[derive(Subcommand)]
enum Commands {
  /// compute hmac for a string
  String {
    /// the secret key (hex encoded or raw string)
    #[arg(short, long)]
    key: String,

    /// the message to authenticate
    message: String,

    /// treat key as hex-encoded
    #[arg(long)]
    key_hex: bool,
  },

  /// compute hmac for a file
  File {
    /// the secret key (hex encoded or raw string)
    #[arg(short, long)]
    key: String,

    /// the file path
    file: PathBuf,

    /// treat key as hex-encoded
    #[arg(long)]
    key_hex: bool,
  },

  /// compute hmac for data from stdin
  Stdin {
    /// the secret key (hex encoded or raw string)
    #[arg(short, long)]
    key: String,

    /// treat key as hex-encoded
    #[arg(long)]
    key_hex: bool,
  },

  /// interactive mode for multiple computations
  Interactive,

  /// benchmark hmac computation performance
  Benchmark {
    /// number of iterations
    #[arg(short, long, default_value = "1000")]
    iterations: usize,

    /// data size in bytes
    #[arg(short, long, default_value = "1024")]
    size: usize,
  },
}

fn parse_key(key_str: &str, is_hex: bool) -> Result<Vec<u8>, String> {
  if is_hex {
    from_hex(key_str)
  } else {
    Ok(key_str.as_bytes().to_vec())
  }
}

fn format_output(hmac: &[u8], format: &str) -> Result<String, String> {
  match format.to_lowercase().as_str() {
    "hex" => Ok(to_hex(hmac)),
    "base64" => Ok(base64_encode(hmac)),
    "raw" => Ok(String::from_utf8_lossy(hmac).to_string()),
    _ => Err("unsupported format. use 'hex', 'base64', or 'raw'".to_string()),
  }
}

fn base64_encode(data: &[u8]) -> String {
  // simple base64 encoding without external crate
  const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let mut result = String::new();

  for chunk in data.chunks(3) {
    let mut buf = [0u8; 3];
    for (i, &byte) in chunk.iter().enumerate() {
      buf[i] = byte;
    }

    let b = ((buf[0] as u32) << 16) | ((buf[1] as u32) << 8) | (buf[2] as u32);

    result.push(CHARS[((b >> 18) & 63) as usize] as char);
    result.push(CHARS[((b >> 12) & 63) as usize] as char);
    result.push(if chunk.len() > 1 {
      CHARS[((b >> 6) & 63) as usize] as char
    } else {
      '='
    });
    result.push(if chunk.len() > 2 {
      CHARS[(b & 63) as usize] as char
    } else {
      '='
    });
  }

  result
}

fn compute_hmac_string(key: &str, message: &str, key_hex: bool, cli: &Cli) -> Result<(), String> {
  let key_bytes = parse_key(key, key_hex)?;
  let message_bytes = message.as_bytes();

  let hmac = hmac_sha256(&key_bytes, message_bytes);
  let formatted = format_output(&hmac, &cli.format)?;

  if let Some(expected) = &cli.verify {
    let matches = formatted.to_lowercase() == expected.to_lowercase();
    if cli.quiet {
      println!("{}", matches);
    } else {
      println!(
        "verification: {}",
        if matches { "✅ PASS" } else { "❌ FAIL" }
      );
      println!("computed: {}", formatted);
      println!("expected: {}", expected);
    }
  } else {
    if cli.quiet {
      println!("{}", formatted);
    } else {
      println!("message: {}", message);
      println!("hmac-sha256: {}", formatted);
    }
  }

  Ok(())
}

fn compute_hmac_file(
  key: &str,
  file_path: &PathBuf,
  key_hex: bool,
  cli: &Cli,
) -> Result<(), String> {
  let key_bytes = parse_key(key, key_hex)?;

  let mut file = File::open(file_path).map_err(|e| format!("failed to open file: {}", e))?;

  let mut buffer = [0u8; 8192];

  // read file in chunks and update hmac
  loop {
    match file.read(&mut buffer) {
      Ok(0) => break, // end of file
      Ok(_) => {
        // we need to recompute for each chunk - this is inefficient
        // in a real implementation, we'd have a streaming hmac
        let mut all_data = Vec::new();
        file
          .read_to_end(&mut all_data)
          .map_err(|e| format!("failed to read file: {}", e))?;

        // go back and read the whole file at once for simplicity
        let mut file =
          File::open(file_path).map_err(|e| format!("failed to reopen file: {}", e))?;
        let mut file_contents = Vec::new();
        file
          .read_to_end(&mut file_contents)
          .map_err(|e| format!("failed to read file: {}", e))?;

        let hmac = hmac_sha256(&key_bytes, &file_contents);
        let formatted = format_output(&hmac, &cli.format)?;

        if let Some(expected) = &cli.verify {
          let matches = formatted.to_lowercase() == expected.to_lowercase();
          if cli.quiet {
            println!("{}", matches);
          } else {
            println!("file: {:?}", file_path);
            println!(
              "verification: {}",
              if matches { "✅ PASS" } else { "❌ FAIL" }
            );
            println!("computed: {}", formatted);
            println!("expected: {}", expected);
          }
        } else {
          if cli.quiet {
            println!("{}", formatted);
          } else {
            println!("file: {:?}", file_path);
            println!("size: {} bytes", file_contents.len());
            println!("hmac-sha256: {}", formatted);
          }
        }
        return Ok(());
      }
      Err(e) => return Err(format!("failed to read file: {}", e)),
    }
  }

  Ok(())
}

fn compute_hmac_stdin(key: &str, key_hex: bool, cli: &Cli) -> Result<(), String> {
  let key_bytes = parse_key(key, key_hex)?;

  let stdin = io::stdin();
  let mut stdin_data = Vec::new();

  for line in stdin.lock().lines() {
    let line = line.map_err(|e| format!("failed to read stdin: {}", e))?;
    stdin_data.extend_from_slice(line.as_bytes());
    stdin_data.push(b'\n');
  }

  // remove trailing newline if present
  if stdin_data.ends_with(&[b'\n']) {
    stdin_data.pop();
  }

  let hmac = hmac_sha256(&key_bytes, &stdin_data);
  let formatted = format_output(&hmac, &cli.format)?;

  if let Some(expected) = &cli.verify {
    let matches = formatted.to_lowercase() == expected.to_lowercase();
    if cli.quiet {
      println!("{}", matches);
    } else {
      println!(
        "verification: {}",
        if matches { "✅ PASS" } else { "❌ FAIL" }
      );
      println!("computed: {}", formatted);
      println!("expected: {}", expected);
    }
  } else {
    if cli.quiet {
      println!("{}", formatted);
    } else {
      println!("input size: {} bytes", stdin_data.len());
      println!("hmac-sha256: {}", formatted);
    }
  }

  Ok(())
}

fn interactive_mode() -> Result<(), String> {
  println!("HMAC-SHA256 Interactive Mode");
  println!("=============================");
  println!("Commands:");
  println!("  hmac <key> <message>     - compute hmac (key and message as strings)");
  println!("  hmac-hex <hex_key> <msg> - compute hmac (key as hex)");
  println!("  verify <key> <msg> <mac> - verify hmac");
  println!("  help                     - show this help");
  println!("  quit                     - exit");
  println!();

  let stdin = io::stdin();
  loop {
    print!("> ");
    io::Write::flush(&mut io::stdout()).unwrap();

    let mut line = String::new();
    stdin
      .read_line(&mut line)
      .map_err(|e| format!("failed to read input: {}", e))?;

    let parts: Vec<&str> = line.trim().split_whitespace().collect();
    if parts.is_empty() {
      continue;
    }

    match parts[0] {
      "quit" | "exit" => break,
      "help" => {
        println!("Commands:");
        println!("  hmac <key> <message>     - compute hmac");
        println!("  hmac-hex <hex_key> <msg> - compute hmac (key as hex)");
        println!("  verify <key> <msg> <mac> - verify hmac");
        println!("  help                     - show this help");
        println!("  quit                     - exit");
      }
      "hmac" => {
        if parts.len() >= 3 {
          let key = parts[1];
          let message = parts[2..].join(" ");
          let hmac = hmac_sha256(key.as_bytes(), message.as_bytes());
          println!("hmac-sha256: {}", to_hex(&hmac));
        } else {
          println!("usage: hmac <key> <message>");
        }
      }
      "hmac-hex" => {
        if parts.len() >= 3 {
          let key_hex = parts[1];
          let message = parts[2..].join(" ");
          match from_hex(key_hex) {
            Ok(key_bytes) => {
              let hmac = hmac_sha256(&key_bytes, message.as_bytes());
              println!("hmac-sha256: {}", to_hex(&hmac));
            }
            Err(e) => println!("error parsing hex key: {}", e),
          }
        } else {
          println!("usage: hmac-hex <hex_key> <message>");
        }
      }
      "verify" => {
        if parts.len() >= 4 {
          let key = parts[1];
          let message = parts[2];
          let expected = parts[3];
          let hmac = hmac_sha256(key.as_bytes(), message.as_bytes());
          let computed = to_hex(&hmac);
          let matches = computed.to_lowercase() == expected.to_lowercase();
          println!(
            "verification: {}",
            if matches { "✅ PASS" } else { "❌ FAIL" }
          );
          println!("computed: {}", computed);
          println!("expected: {}", expected);
        } else {
          println!("usage: verify <key> <message> <expected_hmac>");
        }
      }
      _ => {
        println!("unknown command. type 'help' for available commands.");
      }
    }
  }

  Ok(())
}

fn benchmark(iterations: usize, data_size: usize) -> Result<(), String> {
  use std::time::Instant;

  println!("HMAC-SHA256 Benchmark");
  println!("=====================");
  println!("iterations: {}", iterations);
  println!("data size: {} bytes", data_size);

  let key = b"benchmark_key_12345";
  let data = vec![0x42u8; data_size];

  // warmup
  for _ in 0..10 {
    let _ = hmac_sha256(key, &data);
  }

  let start = Instant::now();
  for _ in 0..iterations {
    let _ = hmac_sha256(key, &data);
  }
  let duration = start.elapsed();

  let total_data = (iterations * data_size) as f64;
  let seconds = duration.as_secs_f64();
  let throughput_mbps = (total_data / (1024.0 * 1024.0)) / seconds;

  println!("total time: {:.2}ms", duration.as_millis());
  println!(
    "time per operation: {:.2}μs",
    duration.as_micros() as f64 / iterations as f64
  );
  println!("throughput: {:.2} MB/s", throughput_mbps);

  Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
  let cli = Cli::parse();

  match cli.command {
    Commands::String {
      ref key,
      ref message,
      key_hex,
    } => {
      compute_hmac_string(&key, &message, key_hex, &cli)?;
    }
    Commands::File {
      ref key,
      ref file,
      key_hex,
    } => {
      compute_hmac_file(&key, &file, key_hex, &cli)?;
    }
    Commands::Stdin { ref key, key_hex } => {
      compute_hmac_stdin(&key, key_hex, &cli)?;
    }
    Commands::Interactive => {
      interactive_mode()?;
    }
    Commands::Benchmark { iterations, size } => {
      benchmark(iterations, size)?;
    }
  }

  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_parse_key() {
    let hex_key = parse_key("48656c6c6f", true).unwrap();
    assert_eq!(hex_key, b"Hello");

    let raw_key = parse_key("Hello", false).unwrap();
    assert_eq!(raw_key, b"Hello");
  }

  #[test]
  fn test_base64_encode() {
    assert_eq!(base64_encode(b"Hello"), "SGVsbG8=");
    assert_eq!(base64_encode(b"Hello World"), "SGVsbG8gV29ybGQ=");
  }

  #[test]
  fn test_format_output() {
    let data = b"Hello World";
    assert_eq!(format_output(data, "hex").unwrap(), to_hex(data));
    assert_eq!(format_output(data, "base64").unwrap(), base64_encode(data));
  }
}
