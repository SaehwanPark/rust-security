use nix::unistd::{ForkResult, Uid, fork, setuid};
use std::io::{Read, Write};
use std::net::TcpListener;

fn main() {
  let listener = TcpListener::bind("127.0.0.1:8080").expect("bind failed");

  match unsafe { fork() } {
    Ok(ForkResult::Parent { .. }) => {
      println!("Privileged parent bound the socket, exiting.");
    }
    Ok(ForkResult::Child) => {
      // Drop privileges — switch to an unprivileged user (e.g., UID 1000)
      setuid(Uid::from_raw(1000)).expect("failed to drop privileges");
      println!("Now running as unprivileged user");

      for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let mut buffer = [0; 512];
        let n = stream.read(&mut buffer).unwrap();
        stream.write_all(&buffer[0..n]).unwrap();
      }
    }
    Err(_) => eprintln!("Fork failed"),
  }
}
