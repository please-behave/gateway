use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

pub fn unused_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve a local port");
    let address = listener.local_addr().expect("read reserved address");
    drop(listener);
    address
}

pub struct Gateway {
    pub child: Child,
    pub address: SocketAddr,
}

impl Gateway {
    pub fn stop(mut self) -> String {
        self.child.kill().expect("stop gateway");
        self.child.wait().expect("wait for gateway");
        let mut logs = String::new();
        self.child
            .stderr
            .take()
            .expect("capture gateway logs")
            .read_to_string(&mut logs)
            .expect("read gateway logs");
        self.child
            .stdout
            .take()
            .expect("capture gateway output")
            .read_to_string(&mut logs)
            .expect("read gateway output");
        logs
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn start_gateway(
    max_body_bytes: usize,
    timeout_ms: usize,
    configure: impl FnOnce(&mut Command),
) -> Gateway {
    let address = unused_address();
    let mut command = super::command(env!("CARGO_BIN_EXE_gateway"));
    command
        .env("GATEWAY_BIND_ADDR", address.to_string())
        .env("GATEWAY_LEDGER_URL", "http://ledger.test")
        .env("GATEWAY_MAX_BODY_BYTES", max_body_bytes.to_string())
        .env("GATEWAY_REQUEST_TIMEOUT_MS", timeout_ms.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure(&mut command);
    let mut child = command.spawn().expect("start gateway");
    for _ in 0..50 {
        if TcpStream::connect(address).is_ok() {
            return Gateway { child, address };
        }
        thread::sleep(Duration::from_millis(10));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("gateway did not start at {address}");
}

pub fn request(address: SocketAddr, request: &str) -> String {
    let mut stream = TcpStream::connect(address).expect("connect to gateway");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set response deadline");
    stream.write_all(request.as_bytes()).expect("send request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");
    response
}
