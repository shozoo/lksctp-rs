//! Loopback integration tests for the synchronous, thread-based API
//! (`SctpSocket` used without tokio; the crate builds identically with
//! `default-features = false`). These exercise the real kernel SCTP stack,
//! so they only run on Linux with the `sctp` module available; otherwise
//! each test skips itself with a note.
//!
//! The async counterpart lives in `loopback_tokio.rs`; shared helpers and
//! protocol encoders in `common/`.

#![cfg(target_os = "linux")]

mod common;

use std::net::SocketAddr;
use std::thread;
use std::time::{Duration, Instant};

use common::{diameter, localhost, m3ua, recv_data_blocking, sctp_available};
use lksctp::{
    AssocChangeState, AssocId, AssocState, EventType, Family, InitParams, Notification, Ppid,
    RecvMsg, RtoInfo, SctpSocket, SendInfo, Style,
};

/// Guards a blocking socket against protocol-level stalls: a stuck recv
/// fails with `WouldBlock` after 10 s instead of hanging the suite.
fn guarded(sock: SctpSocket) -> SctpSocket {
    sock.set_recv_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    sock
}

/// A full Diameter capabilities exchange over blocking sockets, with the
/// client on its own OS thread — the classic thread-per-connection shape.
#[test]
fn blocking_echo_with_metadata() {
    if !sctp_available() {
        return;
    }

    let listener = SctpSocket::new(Family::Ipv4, Style::OneToOne).unwrap();
    listener
        .set_init_params(&InitParams {
            num_ostreams: 8,
            max_instreams: 8,
            ..Default::default()
        })
        .unwrap();
    listener.bind(&localhost(0)).unwrap();
    listener.listen(8).unwrap();
    let server_addr = listener.local_addr().unwrap();

    let client_thread = thread::spawn(move || {
        let client = guarded(SctpSocket::new(Family::Ipv4, Style::OneToOne).unwrap());
        // connectx blocks until the association is established.
        client.connectx(&[server_addr]).unwrap();
        assert_eq!(
            client.status(AssocId::FUTURE).unwrap().state,
            AssocState::Established
        );

        let info = SendInfo {
            sid: 1,
            ppid: Ppid::DIAMETER,
            ..Default::default()
        };
        client
            .send_msg(&diameter::cer("client.example.com", 5, 0x50), &info)
            .unwrap();

        let mut buf = vec![0u8; 4096];
        let (len, rcv) = recv_data_blocking(&client, &mut buf);
        assert_eq!(rcv.sid, 1);
        assert_eq!(rcv.ppid, Ppid::DIAMETER);
        let cea = diameter::parse_header(&buf[..len]);
        assert!(!cea.request);
        assert_eq!(cea.code, diameter::CAPABILITIES_EXCHANGE);
        assert_eq!((cea.hbh, cea.e2e), (5, 0x50));
        assert_eq!(
            diameter::result_code(&buf[..len]),
            Some(diameter::DIAMETER_SUCCESS)
        );
    });

    let (server, peer) = listener.accept().unwrap();
    let server = guarded(server);
    assert_eq!(peer.ip(), server_addr.ip());

    let mut buf = vec![0u8; 4096];
    let (len, rcv) = recv_data_blocking(&server, &mut buf);
    assert_eq!(rcv.sid, 1);
    assert_eq!(rcv.ppid, Ppid::DIAMETER);
    let cer = diameter::parse_header(&buf[..len]);
    assert!(cer.request);
    assert_eq!(
        diameter::find_avp(&buf[..len], diameter::ORIGIN_HOST).unwrap(),
        b"client.example.com"
    );

    server
        .send_msg(
            &diameter::cea(cer.hbh, cer.e2e),
            &SendInfo {
                sid: 1,
                ppid: Ppid::DIAMETER,
                ..Default::default()
            },
        )
        .unwrap();

    client_thread.join().unwrap();
}

/// `set_recv_timeout` turns a blocking recv into a bounded wait that fails
/// with `WouldBlock`, and the socket keeps working afterwards.
#[test]
fn recv_timeout_semantics() {
    if !sctp_available() {
        return;
    }

    let listener = SctpSocket::new(Family::Ipv4, Style::OneToOne).unwrap();
    listener.bind(&localhost(0)).unwrap();
    listener.listen(8).unwrap();

    let client = SctpSocket::new(Family::Ipv4, Style::OneToOne).unwrap();
    // The handshake is completed by the listening socket's kernel side, so
    // a single thread can connect first and accept afterwards.
    client.connect(&listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();

    // Zero durations are rejected, matching std::net.
    assert!(server.set_recv_timeout(Some(Duration::ZERO)).is_err());

    // Getter roundtrip.
    server
        .set_recv_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    assert_eq!(
        server.recv_timeout().unwrap(),
        Some(Duration::from_millis(100))
    );
    server
        .set_send_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    assert_eq!(server.send_timeout().unwrap(), Some(Duration::from_secs(3)));

    // No data pending: recv must give up with WouldBlock after ~100 ms.
    let mut buf = vec![0u8; 4096];
    let start = Instant::now();
    let err = server.recv_msg(&mut buf).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(90) && elapsed < Duration::from_secs(5),
        "timeout fired after {elapsed:?}"
    );

    // Clearing restores block-forever semantics (observed via the getter).
    server.set_recv_timeout(None).unwrap();
    assert_eq!(server.recv_timeout().unwrap(), None);
    server
        .set_recv_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    // The socket still moves data after a timeout.
    client
        .send_msg(
            &diameter::dwr("client.example.com", 1, 2),
            &SendInfo {
                ppid: Ppid::DIAMETER,
                ..Default::default()
            },
        )
        .unwrap();
    let (len, _) = recv_data_blocking(&server, &mut buf);
    assert_eq!(
        diameter::parse_header(&buf[..len]).code,
        diameter::DEVICE_WATCHDOG
    );
}

/// One-to-many endpoints driven entirely from one thread: implicit
/// association setup by an M3UA ASP Up, COMM_UP notifications on both
/// sides, and a reply addressed by association id.
#[test]
fn blocking_one_to_many() {
    if !sctp_available() {
        return;
    }

    let server = guarded(SctpSocket::new(Family::Ipv4, Style::OneToMany).unwrap());
    server.subscribe_events(&[EventType::AssocChange]).unwrap();
    server.bind(&localhost(0)).unwrap();
    server.listen(8).unwrap();
    let server_addr = server.local_addr().unwrap();

    let client = guarded(SctpSocket::new(Family::Ipv4, Style::OneToMany).unwrap());
    client.subscribe_events(&[EventType::AssocChange]).unwrap();

    let info = SendInfo {
        sid: 0,
        ppid: Ppid::M3UA,
        ..Default::default()
    };
    client
        .send_msg_to(&m3ua::ASPUP, &server_addr, &info)
        .unwrap();

    // Client observes COMM_UP for the association it implicitly created.
    let mut buf = vec![0u8; 4096];
    let client_assoc = loop {
        if let RecvMsg::Notification(Notification::AssocChange(ac)) =
            client.recv_msg(&mut buf).unwrap()
        {
            assert_eq!(ac.state, AssocChangeState::CommUp);
            break ac.assoc_id;
        }
    };

    // Server: COMM_UP first, then the ASP Up, with matching assoc ids.
    let mut server_assoc = None;
    let (len, rcv) = loop {
        match server.recv_msg_from(&mut buf).unwrap() {
            (RecvMsg::Notification(Notification::AssocChange(ac)), _) => {
                assert_eq!(ac.state, AssocChangeState::CommUp);
                server_assoc = Some(ac.assoc_id);
            }
            (RecvMsg::Data { len, info, .. }, from) => {
                assert!(from.is_some());
                break (len, info.unwrap());
            }
            (RecvMsg::Notification(_), _) => {}
        }
    };
    assert_eq!(&buf[..len], m3ua::ASPUP);
    assert_eq!(rcv.ppid, Ppid::M3UA);
    let server_assoc = server_assoc.expect("COMM_UP must precede data");
    assert_eq!(rcv.assoc_id, server_assoc);

    server
        .send_msg(
            &m3ua::ASPUP_ACK,
            &SendInfo {
                ppid: Ppid::M3UA,
                assoc_id: server_assoc,
                ..Default::default()
            },
        )
        .unwrap();
    loop {
        if let RecvMsg::Data { len, info, .. } = client.recv_msg(&mut buf).unwrap() {
            assert_eq!(&buf[..len], m3ua::ASPUP_ACK);
            assert_eq!(info.unwrap().assoc_id, client_assoc);
            break;
        }
    }
}

/// Thread-per-connection server: one listening socket, several client
/// threads connecting concurrently, one handler thread per accepted
/// association.
#[test]
fn thread_per_connection_server() {
    if !sctp_available() {
        return;
    }
    const N: u32 = 4;

    let listener = SctpSocket::new(Family::Ipv4, Style::OneToOne).unwrap();
    listener.bind(&localhost(0)).unwrap();
    listener.listen(8).unwrap();
    let server_addr = listener.local_addr().unwrap();

    let clients: Vec<_> = (0..N)
        .map(|i| {
            thread::spawn(move || {
                let client = guarded(SctpSocket::new(Family::Ipv4, Style::OneToOne).unwrap());
                client.connectx(&[server_addr]).unwrap();
                let host = format!("client{i}.example.com");
                let info = SendInfo {
                    ppid: Ppid::DIAMETER,
                    ..Default::default()
                };
                client
                    .send_msg(&diameter::cer(&host, i, 0x7000 + i), &info)
                    .unwrap();

                let mut buf = vec![0u8; 4096];
                let (len, _) = recv_data_blocking(&client, &mut buf);
                let cea = diameter::parse_header(&buf[..len]);
                assert!(!cea.request);
                // Identifier echo doubles as the isolation check.
                assert_eq!((cea.hbh, cea.e2e), (i, 0x7000 + i));
                assert_eq!(
                    diameter::result_code(&buf[..len]),
                    Some(diameter::DIAMETER_SUCCESS)
                );
            })
        })
        .collect();

    let mut handlers = Vec::new();
    for _ in 0..N {
        let (stream, _) = listener.accept().unwrap();
        let stream = guarded(stream);
        handlers.push(thread::spawn(move || {
            let mut buf = vec![0u8; 4096];
            let (len, _) = recv_data_blocking(&stream, &mut buf);
            let cer = diameter::parse_header(&buf[..len]);
            assert!(cer.request);
            assert_eq!(cer.code, diameter::CAPABILITIES_EXCHANGE);
            assert_eq!(
                diameter::find_avp(&buf[..len], diameter::ORIGIN_HOST).unwrap(),
                format!("client{}.example.com", cer.hbh).into_bytes()
            );
            stream
                .send_msg(
                    &diameter::cea(cer.hbh, cer.e2e),
                    &SendInfo {
                        ppid: Ppid::DIAMETER,
                        ..Default::default()
                    },
                )
                .unwrap();
            cer.hbh
        }));
    }

    let mut ids: Vec<u32> = handlers.into_iter().map(|h| h.join().unwrap()).collect();
    ids.sort_unstable();
    assert_eq!(ids, (0..N).collect::<Vec<_>>());
    for c in clients {
        c.join().unwrap();
    }
}

/// Socket option get/set roundtrips (no association involved).
#[test]
fn socket_options_roundtrip() {
    if !sctp_available() {
        return;
    }

    let sock = SctpSocket::new(Family::Ipv4, Style::OneToOne).unwrap();
    sock.set_nodelay(true).unwrap();
    assert!(sock.nodelay().unwrap());

    // Stay under net.core.{r,w}mem_max (208 KiB by default) so the request
    // is not silently capped; the kernel stores (at least) double the value.
    sock.set_recv_buffer_size(64 * 1024).unwrap();
    assert!(sock.recv_buffer_size().unwrap() >= 64 * 1024);
    sock.set_send_buffer_size(64 * 1024).unwrap();
    assert!(sock.send_buffer_size().unwrap() >= 64 * 1024);

    let init = InitParams {
        num_ostreams: 17,
        max_instreams: 33,
        ..Default::default()
    };
    sock.set_init_params(&init).unwrap();
    let got = sock.init_params().unwrap();
    assert_eq!(got.num_ostreams, 17);
    assert_eq!(got.max_instreams, 33);

    // RTO bounds roundtrip (endpoint defaults; milliseconds).
    let rto = RtoInfo {
        initial: 500,
        max: 2000,
        min: 200,
    };
    sock.set_rto_info(AssocId::FUTURE, &rto).unwrap();
    assert_eq!(sock.rto_info(AssocId::FUTURE).unwrap(), rto);

    // Event subscription toggles both ways.
    sock.subscribe_event(EventType::PeerAddrChange, true)
        .unwrap();
    sock.subscribe_event(EventType::PeerAddrChange, false)
        .unwrap();

    // Autoclose is a one-to-many-only option.
    let ep = SctpSocket::new(Family::Ipv4, Style::OneToMany).unwrap();
    ep.set_autoclose(30).unwrap();
    assert!(
        sock.set_autoclose(30).is_err(),
        "autoclose must be rejected on one-to-one"
    );
}

/// bindx add/remove drives the endpoint's local address list, observable
/// via local_addrs(). Uses two loopback addresses (127.0.0.1 / 127.0.0.2).
#[test]
fn bindx_multihoming() {
    if !sctp_available() {
        return;
    }

    let sock = SctpSocket::new(Family::Ipv4, Style::OneToOne).unwrap();
    // First bindx picks an ephemeral port; further addresses must reuse it.
    sock.bindx_add(&[localhost(0)]).unwrap();
    let port = sock.local_addr().unwrap().port();
    let second: SocketAddr = format!("127.0.0.2:{port}").parse().unwrap();

    sock.bindx_add(&[second]).unwrap();
    let addrs = sock.local_addrs(AssocId::FUTURE).unwrap();
    assert_eq!(addrs.len(), 2, "expected two bound addresses: {addrs:?}");
    assert!(addrs.contains(&localhost(port)));
    assert!(addrs.contains(&second));

    sock.bindx_remove(&[second]).unwrap();
    let addrs = sock.local_addrs(AssocId::FUTURE).unwrap();
    assert_eq!(addrs, vec![localhost(port)]);
}

/// A notification larger than the receive buffer must be reassembled
/// internally and returned whole — not error out and desynchronize the
/// stream (the shutdown notification is 12 bytes; the buffer holds 8).
#[test]
fn notification_reassembled_with_tiny_buffer() {
    if !sctp_available() {
        return;
    }

    let listener = SctpSocket::new(Family::Ipv4, Style::OneToOne).unwrap();
    listener.bind(&localhost(0)).unwrap();
    listener.listen(8).unwrap();

    let client = SctpSocket::new(Family::Ipv4, Style::OneToOne).unwrap();
    client.connect(&listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    let server = guarded(server);
    server
        .subscribe_events(&[EventType::Shutdown, EventType::AssocChange])
        .unwrap();

    client.shutdown(std::net::Shutdown::Write).unwrap();

    let mut tiny = [0u8; 8];
    let mut saw_shutdown = false;
    loop {
        match server.recv_msg(&mut tiny).unwrap() {
            RecvMsg::Notification(Notification::Shutdown(_)) => saw_shutdown = true,
            RecvMsg::Notification(Notification::AssocChange(ac))
                if ac.state == AssocChangeState::ShutdownComplete =>
            {
                break;
            }
            RecvMsg::Data { len: 0, .. } => break,
            _ => {}
        }
    }
    assert!(
        saw_shutdown,
        "shutdown notification must survive reassembly"
    );
}

/// Blocking connect to a closed port fails with ECONNREFUSED.
#[test]
fn connect_refused_blocking() {
    if !sctp_available() {
        return;
    }

    let probe = SctpSocket::new(Family::Ipv4, Style::OneToOne).unwrap();
    probe.bind(&localhost(0)).unwrap();
    let dead_addr = probe.local_addr().unwrap();
    drop(probe);

    let client = SctpSocket::new(Family::Ipv4, Style::OneToOne).unwrap();
    let err = client
        .connectx(&[dead_addr])
        .expect_err("connect to a closed port must fail");
    assert_eq!(
        err.raw_os_error(),
        Some(111),
        "expected ECONNREFUSED: {err:?}"
    );
}

/// A genuinely multi-homed association (two loopback paths on both sides):
/// address enumeration, per-path state, and per-path parameter tuning.
#[test]
fn multihomed_two_paths() {
    if !sctp_available() {
        return;
    }

    // Server bound to 127.0.0.1 and 127.0.0.2 on one port.
    let listener = SctpSocket::new(Family::Ipv4, Style::OneToOne).unwrap();
    listener.bindx_add(&[localhost(0)]).unwrap();
    let s_port = listener.local_addr().unwrap().port();
    let s_addr2: SocketAddr = format!("127.0.0.2:{s_port}").parse().unwrap();
    listener.bindx_add(&[s_addr2]).unwrap();
    listener.listen(8).unwrap();

    // Client likewise; both its addresses are announced in the INIT.
    let client = guarded(SctpSocket::new(Family::Ipv4, Style::OneToOne).unwrap());
    client.bindx_add(&[localhost(0)]).unwrap();
    let c_port = client.local_addr().unwrap().port();
    let c_addr2: SocketAddr = format!("127.0.0.2:{c_port}").parse().unwrap();
    client.bindx_add(&[c_addr2]).unwrap();

    client.connectx(&[localhost(s_port), s_addr2]).unwrap();
    let (server, _) = listener.accept().unwrap();
    let server = guarded(server);

    // Both sides must see both paths of the peer.
    let client_view = client.peer_addrs(AssocId::FUTURE).unwrap();
    assert_eq!(
        client_view.len(),
        2,
        "client should see two peer paths: {client_view:?}"
    );
    assert!(client_view.contains(&localhost(s_port)));
    assert!(client_view.contains(&s_addr2));

    let server_view = server.peer_addrs(AssocId::FUTURE).unwrap();
    assert_eq!(
        server_view.len(),
        2,
        "server should see two peer paths: {server_view:?}"
    );
    assert!(server_view.contains(&localhost(c_port)));
    assert!(server_view.contains(&c_addr2));

    // Per-path state: the primary is active; the alternate path may still
    // be unconfirmed until a heartbeat completes.
    use lksctp::PeerAddrState;
    let primary = client.status(AssocId::FUTURE).unwrap().primary;
    assert_eq!(primary.state, PeerAddrState::Active);
    for path in &client_view {
        let info = client.peer_addr_info(AssocId::FUTURE, path).unwrap();
        assert!(
            matches!(
                info.state,
                PeerAddrState::Active | PeerAddrState::Unconfirmed
            ),
            "unexpected path state for {path}: {info:?}"
        );
        assert!(info.mtu > 0);
    }

    // Tune per-path parameters on the alternate path and read them back.
    let params = lksctp::PeerAddrParams {
        hb_interval: 5_000,
        path_max_rxt: 3,
        flags: lksctp::SppFlags::HB_ENABLE,
        ..Default::default()
    };
    client
        .set_peer_addr_params(AssocId::FUTURE, Some(&s_addr2), &params)
        .unwrap();
    let got = client
        .peer_addr_params(AssocId::FUTURE, Some(&s_addr2))
        .unwrap();
    assert_eq!(got.hb_interval, 5_000);
    assert_eq!(got.path_max_rxt, 3);
    assert!(got.flags.contains(lksctp::SppFlags::HB_ENABLE));

    // Data still flows over the multi-homed association.
    client
        .send_msg(
            &m3ua::ASPUP,
            &SendInfo {
                ppid: Ppid::M3UA,
                ..Default::default()
            },
        )
        .unwrap();
    let mut buf = vec![0u8; 4096];
    let (len, _) = recv_data_blocking(&server, &mut buf);
    assert_eq!(&buf[..len], m3ua::ASPUP);
}
