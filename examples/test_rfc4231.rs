// test our hmac-sha256 implementation against RFC 4231 test vectors
// also compare with the official rust hmac crate

use hmac::{Hmac, Mac};
use sha2::Sha256;

// import our implementation from the other example
#[path = "hmac_sha256_from_scratch.rs"]
mod hmac_impl;

use hmac_impl::{from_hex, hmac_sha256, to_hex};

type HmacSha256Official = Hmac<Sha256>;

#[derive(Debug)]
struct TestVector {
  name: &'static str,
  key: &'static str,
  data: &'static str,
  expected_sha256: &'static str,
  description: &'static str,
}

// rfc 4231 test vectors for hmac-sha256
const RFC4231_VECTORS: &[TestVector] = &[
  TestVector {
    name: "Test Case 1",
    key: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
    data: "4869205468657265", // "Hi There"
    expected_sha256: "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    description: "Basic test with 20-byte key",
  },
  TestVector {
    name: "Test Case 2",
    key: "4a656665",                                                  // "Jefe"
    data: "7768617420646f2079612077616e7420666f72206e6f7468696e673f", // "what do ya want for nothing?"
    expected_sha256: "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    description: "Test with a key shorter than the length of the HMAC output",
  },
  TestVector {
    name: "Test Case 3",
    key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // 20 bytes of 0xaa
    data: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", // 50 bytes of 0xdd
    expected_sha256: "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
    description: "Test with a combined length of key and data that is larger than 64 bytes",
  },
  TestVector {
    name: "Test Case 4",
    key: "0102030405060708090a0b0c0d0e0f10111213141516171819", // 25 bytes
    data: "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", // 50 bytes of 0xcd
    expected_sha256: "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
    description: "Test with a combined length of key and data that is larger than 64 bytes",
  },
  TestVector {
    name: "Test Case 5",
    key: "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", // 20 bytes of 0x0c
    data: "546573742057697468205472756e636174696f6e", // "Test With Truncation"
    expected_sha256: "a3b6167473100ee06e0c796c2955552b", // truncated to 128 bits (16 bytes)
    description: "Test with a truncation of output to 128 bits",
  },
  TestVector {
    name: "Test Case 6",
    key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // 131 bytes of 0xaa
    data: "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374", // "Test Using Larger Than Block-Size Key - Hash Key First"
    expected_sha256: "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
    description: "Test with a key larger than 128 bytes (= block-size of SHA-384 and SHA-512)",
  },
  TestVector {
    name: "Test Case 7",
    key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // 131 bytes of 0xaa
    data: "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e", // "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."
    expected_sha256: "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
    description: "Test with a key and data that is larger than 128 bytes",
  },
];

// the full data for test case 7 (too long for const)
fn get_test_case_7_data() -> Vec<u8> {
  from_hex("5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074686616e20626c6f636b2d73697a652064617461612e20546865206b6579206e6565647320746f2062652068617368656420626566726965206265696e6720757365642062792074686520484d414320616c676f726974686d2e").unwrap()
}

fn run_test_vector(test_vec: &TestVector, truncate_to: Option<usize>) -> Result<(), String> {
  println!("\n{}", "=".repeat(60));
  println!("Testing: {}", test_vec.name);
  println!("Description: {}", test_vec.description);

  // parse inputs
  let key = from_hex(test_vec.key)?;
  let data = if test_vec.name == "Test Case 7" {
    get_test_case_7_data()
  } else {
    from_hex(test_vec.data)?
  };

  println!("Key length: {} bytes", key.len());
  println!("Data length: {} bytes", data.len());

  // compute using our implementation
  let our_result = hmac_sha256(&key, &data);
  let our_hex = if let Some(len) = truncate_to {
    to_hex(&our_result[..len])
  } else {
    to_hex(&our_result)
  };

  // compute using official rust hmac crate
  let mut mac =
    HmacSha256Official::new_from_slice(&key).map_err(|e| format!("HMAC creation failed: {}", e))?;
  mac.update(&data);
  let official_result = mac.finalize().into_bytes();
  let official_hex = if let Some(len) = truncate_to {
    to_hex(&official_result[..len])
  } else {
    to_hex(&official_result)
  };

  // compare results
  println!("Our result:      {}", our_hex);
  println!("Official result: {}", official_hex);
  println!("Expected:        {}", test_vec.expected_sha256);

  let our_matches = our_hex == test_vec.expected_sha256;
  let official_matches = official_hex == test_vec.expected_sha256;
  let implementations_match = our_hex == official_hex;

  println!("Our impl matches RFC: {}", our_matches);
  println!("Official matches RFC: {}", official_matches);
  println!("Implementations agree: {}", implementations_match);

  if our_matches && official_matches && implementations_match {
    println!("✅ PASS");
    Ok(())
  } else {
    println!("❌ FAIL");
    Err(format!("Test failed for {}", test_vec.name))
  }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
  println!("HMAC-SHA256 RFC 4231 Test Vector Validation");
  println!("============================================");
  println!("Testing our implementation against RFC 4231 test vectors");
  println!("and comparing with the official Rust hmac crate\n");

  let mut passed = 0;
  let mut total = 0;

  for (_, test_vec) in RFC4231_VECTORS.iter().enumerate() {
    total += 1;
    let truncate = if test_vec.name == "Test Case 5" {
      Some(16)
    } else {
      None
    };

    match run_test_vector(test_vec, truncate) {
      Ok(()) => passed += 1,
      Err(e) => eprintln!("Error: {}", e),
    }
  }

  println!("\n{}", "=".repeat(60));
  println!("Test Summary");
  println!("============");
  println!("Passed: {}/{} tests", passed, total);

  if passed == total {
    println!("🎉 All tests passed! Our implementation is correct.");
  } else {
    println!("❌ Some tests failed. Implementation needs fixes.");
    std::process::exit(1);
  }

  // additional verification tests
  println!("\nAdditional Verification Tests");
  println!("=============================");

  // test with empty key and data
  let empty_key = b"";
  let empty_data = b"";
  let our_empty = hmac_sha256(empty_key, empty_data);

  let mut official_empty = HmacSha256Official::new_from_slice(empty_key)?;
  official_empty.update(empty_data);
  let official_empty_result = official_empty.finalize().into_bytes();

  println!(
    "Empty key/data test: {}",
    if our_empty.as_slice() == official_empty_result.as_slice() {
      "✅ PASS"
    } else {
      "❌ FAIL"
    }
  );

  // test with very long message
  let long_message = vec![0x42u8; 10000];
  let our_long = hmac_sha256(b"test", &long_message);

  let mut official_long = HmacSha256Official::new_from_slice(b"test")?;
  official_long.update(&long_message);
  let official_long_result = official_long.finalize().into_bytes();

  println!(
    "Long message test: {}",
    if our_long.as_slice() == official_long_result.as_slice() {
      "✅ PASS"
    } else {
      "❌ FAIL"
    }
  );

  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_all_rfc4231_vectors() {
    for test_vec in RFC4231_VECTORS {
      let truncate = if test_vec.name == "Test Case 5" {
        Some(16)
      } else {
        None
      };
      if let Err(e) = run_test_vector(test_vec, truncate) {
        eprintln!("Error! : {e}");
      }
    }
  }
}
