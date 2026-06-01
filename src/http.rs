// src/http.rs
extern crate alloc;
use alloc::format;
use alloc::string::String;

pub fn handle_request(payload: &[u8]) -> Option<String> {
    let request = String::from_utf8_lossy(payload);

    // Check for standard HTTP GET pattern
    if request.contains("GET /") {
        let body = "<html>\n\
<head><title>Isla Stack</title></head>\n\
<body style=\"font-family: sans-serif; background: #121212; color: #00ffcc; text-align: center; padding-top: 50px;\">\n\
<h1>Project Isla</h1>\n\
<p>This page was served by a custom, stackless Rust TCP/IP implementation.</p>\n\
<hr style=\"border: 1px solid #333; width: 50%;\">\n\
<p style=\"color: #888;\">Bypassing the Linux Kernel :P</p>\n\
</body>\n\
</html>";

        let response = format!(
            "HTTP/1.1 200 OK\r\n\
Content-Type: text/html\r\n\
Content-Length: {}\r\n\
Connection: close\r\n\
Server: Isla-User-Stack/1.0\r\n\
\r\n\
{}",
            body.len(),
            body
        );

        Some(response)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_handler() {
        let request = b"GET /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let response = handle_request(request).unwrap();
        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains("Project Isla"));
    }

    #[test]
    fn test_http_invalid() {
        let request = b"POST /submit HTTP/1.1\r\n\r\n";
        assert!(handle_request(request).is_none());
    }
}
