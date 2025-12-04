#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!(
        "This starter listens to the Linux audit netlink socket. Build and run on Linux."
    );
}

#[cfg(target_os = "linux")]
fn main() {
    use std::mem;
    use std::os::raw::c_void;

    unsafe {
        let fd = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_AUDIT);
        if fd < 0 {
            eprintln!("socket() failed: {}", std::io::Error::last_os_error());
            std::process::exit(1);
        }

        let mut addr: libc::sockaddr_nl = mem::zeroed();
        // bind to this process id and listen on group 1 (audit messages)
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        // nl_pid is u32 on Linux
        addr.nl_pid = libc::getpid() as u32;
        addr.nl_groups = 1u32;

        let ret = libc::bind(
            fd,
            &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        );

        if ret < 0 {
            eprintln!("bind() failed: {}", std::io::Error::last_os_error());
            libc::close(fd);
            std::process::exit(1);
        }

        println!("Listening for audit netlink messages (fd={})", fd);

        let mut buf = vec![0u8; 8192];
        loop {
            let len = libc::recv(
                fd,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                0,
            );
            if len < 0 {
                eprintln!("recv() failed: {}", std::io::Error::last_os_error());
                break;
            }
            if len == 0 {
                eprintln!("recv returned 0, no more data");
                break;
            }

            let slice = &buf[..(len as usize)];
            match std::str::from_utf8(slice) {
                Ok(s) => println!("---[MSG]---\n{}\n", s),
                Err(_) => println!("---[RAW {} bytes]---\n{:02x?}\n", len, slice),
            }
        }

        libc::close(fd);
    }
}
