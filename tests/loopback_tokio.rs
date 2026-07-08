//! Loopback integration tests for the tokio-based async API. These exercise
//! the real kernel SCTP stack, so they only run on Linux with the `sctp`
//! module available; otherwise each test skips itself with a note.
//!
//! The blocking (thread-based) counterpart lives in `loopback_blocking.rs`;
//! shared helpers and protocol encoders in `common/`.

#![cfg(all(target_os = "linux", feature = "tokio"))]

mod common;

use std::net::Shutdown;

use common::{diameter, localhost, m3ua, recv_data, sctp_available, t};
use lksctp::{
    AssocChangeState, AssocId, AssocState, EventType, Family, InitParams, Notification,
    PeerAddrState, Ppid, RecvMsg, SctpEndpoint, SctpListener, SctpSocket, SctpStream, SendFlags,
    SendInfo, Style,
};

#[tokio::test]
async fn one_to_one_echo_with_metadata() {
    if !sctp_available() {
        return;
    }

    let listener = SctpListener::builder(Family::Ipv4)
        .unwrap()
        .init_params(&InitParams {
            num_ostreams: 8,
            max_instreams: 8,
            ..Default::default()
        })
        .unwrap()
        .bindx(&[localhost(0)])
        .unwrap()
        .listen(8)
        .unwrap();
    let server_addr = listener.local_addr().unwrap();

    let client_task = tokio::spawn(async move {
        let stream = SctpStream::builder(Family::Ipv4)
            .unwrap()
            .init_params(&InitParams {
                num_ostreams: 4,
                max_instreams: 4,
                ..Default::default()
            })
            .unwrap()
            .connectx(&[server_addr])
            .await
            .unwrap();

        // Negotiated streams: min(client ostreams 4, server instreams 8) = 4.
        let status = stream.status(AssocId::FUTURE).unwrap();
        assert_eq!(status.state, AssocState::Established);
        assert_eq!(status.outstrms, 4);

        // Diameter capabilities exchange; RFC 6733 permits any stream, so
        // sid 2 also exercises stream selection.
        let info = SendInfo {
            sid: 2,
            ppid: Ppid::DIAMETER,
            context: 77,
            ..Default::default()
        };
        stream
            .send_msg(&diameter::cer("client.example.com", 42, 0x9999), &info)
            .await
            .unwrap();

        let mut buf = vec![0u8; 4096];
        let (len, rcv) = recv_data(&stream, &mut buf).await;
        assert_eq!(rcv.sid, 2);
        assert_eq!(rcv.ppid, Ppid::DIAMETER);
        let hdr = diameter::parse_header(&buf[..len]);
        assert!(!hdr.request);
        assert_eq!(hdr.code, diameter::CAPABILITIES_EXCHANGE);
        // Answers echo the request's identifiers (RFC 6733 §6.2).
        assert_eq!((hdr.hbh, hdr.e2e), (42, 0x9999));
        assert_eq!(
            diameter::result_code(&buf[..len]),
            Some(diameter::DIAMETER_SUCCESS)
        );
    });

    let (stream, peer) = listener.accept().await.unwrap();
    assert_eq!(peer.ip(), server_addr.ip());

    let mut buf = vec![0u8; 4096];
    let (len, rcv) = recv_data(&stream, &mut buf).await;
    assert_eq!(rcv.sid, 2);
    assert_eq!(rcv.ppid, Ppid::DIAMETER);
    let cer = diameter::parse_header(&buf[..len]);
    assert!(cer.request);
    assert_eq!(cer.code, diameter::CAPABILITIES_EXCHANGE);
    assert_eq!(
        diameter::find_avp(&buf[..len], diameter::ORIGIN_HOST).unwrap(),
        b"client.example.com"
    );

    // The accepted stream is a full symmetric peer: introspection and
    // sending work the same as on the connecting side.
    let status = stream.status(AssocId::FUTURE).unwrap();
    assert_eq!(status.state, AssocState::Established);
    assert_eq!(status.instrms, 4);
    let pinfo = stream.peer_addr_info(AssocId::FUTURE, &peer).unwrap();
    assert_eq!(pinfo.state, PeerAddrState::Active);
    assert_eq!(pinfo.address, Some(peer));
    assert!(pinfo.cwnd > 0, "cwnd should be positive: {pinfo:?}");
    assert!(pinfo.mtu > 0, "path MTU should be positive: {pinfo:?}");
    assert!(pinfo.rto > 0, "RTO should be positive: {pinfo:?}");
    assert!(!stream.peer_addrs(AssocId::FUTURE).unwrap().is_empty());
    assert!(!stream.local_addrs(AssocId::FUTURE).unwrap().is_empty());
    // Requesting the (only) peer address as primary path must succeed.
    stream.set_primary(AssocId::FUTURE, &peer).unwrap();

    stream
        .send_msg(
            &diameter::cea(cer.hbh, cer.e2e),
            &SendInfo {
                sid: 2,
                ppid: Ppid::DIAMETER,
                ..Default::default()
            },
        )
        .await
        .unwrap();

    client_task.await.unwrap();
}

#[tokio::test]
async fn one_to_one_shutdown_notification() {
    if !sctp_available() {
        return;
    }

    let listener = SctpListener::builder(Family::Ipv4)
        .unwrap()
        .subscribe_events(&[EventType::Shutdown, EventType::AssocChange])
        .unwrap()
        .bindx(&[localhost(0)])
        .unwrap()
        .listen(8)
        .unwrap();
    let server_addr = listener.local_addr().unwrap();

    let client_task = tokio::spawn(async move {
        // The shutdown *initiator* does not get EOF semantics (the kernel
        // only sets RCV_SHUTDOWN on the side that receives the SHUTDOWN
        // chunk), so completion must be observed via AssocChange.
        let stream = SctpStream::builder(Family::Ipv4)
            .unwrap()
            .subscribe_events(&[EventType::AssocChange])
            .unwrap()
            .connectx(&[server_addr])
            .await
            .unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        let mut buf = vec![0u8; 4096];
        loop {
            match t(stream.recv_msg(&mut buf)).await {
                Ok(RecvMsg::Notification(Notification::AssocChange(ac)))
                    if ac.state == AssocChangeState::ShutdownComplete =>
                {
                    break;
                }
                Ok(RecvMsg::Data { len: 0, .. }) | Err(_) => break,
                Ok(_) => {}
            }
        }
    });

    let (stream, _) = t(listener.accept()).await.unwrap();

    let mut buf = vec![0u8; 4096];
    let mut saw_shutdown = false;
    loop {
        match t(stream.recv_msg(&mut buf)).await {
            Ok(RecvMsg::Notification(Notification::Shutdown(_))) => saw_shutdown = true,
            Ok(RecvMsg::Notification(Notification::AssocChange(ac)))
                if ac.state == AssocChangeState::ShutdownComplete =>
            {
                break;
            }
            Ok(RecvMsg::Data { len: 0, .. }) => break, // association fully closed
            Ok(_) => {}
            Err(e) => panic!("recv failed: {e}"),
        }
    }
    assert!(saw_shutdown, "expected SCTP_SHUTDOWN_EVENT");
    client_task.await.unwrap();
}

#[tokio::test]
async fn one_to_many_implicit_setup_and_events() {
    if !sctp_available() {
        return;
    }

    let server = SctpEndpoint::builder(Family::Ipv4)
        .unwrap()
        .subscribe_events(&[EventType::AssocChange])
        .unwrap()
        .bindx(&[localhost(0)])
        .unwrap()
        .listen(8)
        .unwrap();
    let server_addr = server.local_addr().unwrap();

    let client = SctpEndpoint::builder(Family::Ipv4)
        .unwrap()
        .subscribe_events(&[EventType::AssocChange])
        .unwrap()
        .build()
        .unwrap();

    // Implicit association setup: the first send establishes it. An M3UA
    // ASP Up is exactly what a SIGTRAN peer would send here.
    let info = SendInfo {
        sid: 0,
        ppid: Ppid::M3UA,
        ..Default::default()
    };
    client
        .send_msg_to(&m3ua::ASPUP, &server_addr, &info)
        .await
        .unwrap();

    // Client observes COMM_UP for the association it just created.
    let mut buf = vec![0u8; 4096];
    let client_assoc = loop {
        if let RecvMsg::Notification(Notification::AssocChange(ac)) =
            client.recv_msg(&mut buf).await.unwrap()
        {
            assert_eq!(ac.state, AssocChangeState::CommUp);
            break ac.assoc_id;
        }
    };
    assert_ne!(client_assoc, AssocId(0));

    // Server sees COMM_UP first, then the data, with matching assoc ids.
    let mut server_assoc = None;
    let (len, rcv) = loop {
        match server.recv_msg_from(&mut buf).await.unwrap() {
            (RecvMsg::Notification(Notification::AssocChange(ac)), _) => {
                assert_eq!(ac.state, AssocChangeState::CommUp);
                server_assoc = Some(ac.assoc_id);
            }
            (RecvMsg::Data { len, info, .. }, from) => {
                assert!(from.is_some(), "recv_msg_from reports the source address");
                break (len, info.unwrap());
            }
            (RecvMsg::Notification(_), _) => {}
        }
    };
    assert_eq!(&buf[..len], m3ua::ASPUP);
    assert_eq!(rcv.ppid, Ppid::M3UA);
    let server_assoc = server_assoc.expect("COMM_UP must precede data");
    assert_eq!(rcv.assoc_id, server_assoc);

    // Reply addressed purely by association id.
    server
        .send_msg(
            &m3ua::ASPUP_ACK,
            &SendInfo {
                ppid: Ppid::M3UA,
                assoc_id: server_assoc,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    loop {
        if let RecvMsg::Data { len, info, .. } = client.recv_msg(&mut buf).await.unwrap() {
            assert_eq!(&buf[..len], m3ua::ASPUP_ACK);
            assert_eq!(info.unwrap().assoc_id, client_assoc);
            break;
        }
    }

    // Peel the association off into a one-to-one stream and use it.
    let peeled = server.peeloff(server_assoc).unwrap();
    assert_eq!(
        peeled.status(AssocId::FUTURE).unwrap().state,
        AssocState::Established
    );
    let beat = m3ua::beat(b"peeled");
    peeled
        .send_msg(
            &beat,
            &SendInfo {
                ppid: Ppid::M3UA,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    loop {
        if let RecvMsg::Data { len, .. } = client.recv_msg(&mut buf).await.unwrap() {
            assert_eq!(&buf[..len], &beat[..]);
            break;
        }
    }
}

#[tokio::test]
async fn one_to_many_explicit_connectx() {
    if !sctp_available() {
        return;
    }

    let server = SctpEndpoint::bind(localhost(0)).unwrap();
    let server_addr = server.local_addr().unwrap();

    let client = SctpEndpoint::builder(Family::Ipv4)
        .unwrap()
        .subscribe_events(&[EventType::AssocChange])
        .unwrap()
        .build()
        .unwrap();
    let assoc = client.connectx(&[server_addr]).unwrap();
    assert_ne!(assoc, AssocId(0));

    // Establishment is reported via COMM_UP carrying the same assoc id.
    let mut buf = vec![0u8; 4096];
    loop {
        if let RecvMsg::Notification(Notification::AssocChange(ac)) =
            client.recv_msg(&mut buf).await.unwrap()
        {
            assert_eq!(ac.state, AssocChangeState::CommUp);
            assert_eq!(ac.assoc_id, assoc);
            break;
        }
    }
    assert_eq!(client.status(assoc).unwrap().state, AssocState::Established);
}

#[tokio::test]
async fn concurrent_streams_over_arc() {
    if !sctp_available() {
        return;
    }

    let listener = SctpListener::bind(localhost(0)).unwrap();
    let server_addr = listener.local_addr().unwrap();

    let client_task = tokio::spawn(async move {
        let stream = std::sync::Arc::new(SctpStream::connect(server_addr).await.unwrap());

        // &self-based API: reader and writer tasks share one stream.
        let reader = {
            let stream = stream.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                for _ in 0..10 {
                    let (len, info) = recv_data(&stream, &mut buf).await;
                    // The answer must come back on the sid its request was
                    // sent on: DWR i went out with hbh = i on sid = i % 4.
                    let hdr = diameter::parse_header(&buf[..len]);
                    assert!(!hdr.request);
                    assert_eq!(hdr.code, diameter::DEVICE_WATCHDOG);
                    assert_eq!(info.sid, (hdr.hbh % 4) as u16);
                }
            })
        };
        for i in 0..10u32 {
            let info = SendInfo {
                sid: (i % 4) as u16,
                ppid: Ppid::DIAMETER,
                ..Default::default()
            };
            stream
                .send_msg(&diameter::dwr("client.example.com", i, 0x4000 + i), &info)
                .await
                .unwrap();
        }
        reader.await.unwrap();
    });

    let (stream, _) = listener.accept().await.unwrap();
    let mut buf = vec![0u8; 4096];
    for _ in 0..10 {
        let (len, info) = recv_data(&stream, &mut buf).await;
        let hdr = diameter::parse_header(&buf[..len]);
        assert!(hdr.request);
        // Answer the watchdog on the stream id it arrived on.
        let reply = SendInfo {
            sid: info.sid,
            ppid: Ppid::DIAMETER,
            ..Default::default()
        };
        stream
            .send_msg(&diameter::dwa(hdr.hbh, hdr.e2e), &reply)
            .await
            .unwrap();
    }

    client_task.await.unwrap();
}

/// One listening socket serving several concurrent one-to-one clients:
/// every client gets its own association/stream, answers are never crossed
/// between clients, and one client's shutdown leaves the rest working.
/// Modeled as a Diameter server with N peers doing CER/CEA then DWR/DWA.
#[tokio::test]
async fn one_to_one_multiple_concurrent_clients() {
    if !sctp_available() {
        return;
    }
    const N: u32 = 8;

    let listener = SctpListener::bind(localhost(0)).unwrap();
    let server_addr = listener.local_addr().unwrap();

    // Fires once the server has observed client 0's departure.
    let (gone_tx, mut gone_rx) = tokio::sync::mpsc::channel::<()>(1);
    // Then releases the surviving clients for their watchdog exchange.
    let (go_tx, _) = tokio::sync::broadcast::channel::<()>(1);

    let server = tokio::spawn(async move {
        let mut handlers = Vec::new();
        for _ in 0..N {
            let (stream, _peer) = t(listener.accept()).await.unwrap();
            let gone_tx = gone_tx.clone();
            handlers.push(tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                // Every association starts with a CER identifying the client.
                let (len, info) = recv_data(&stream, &mut buf).await;
                assert_eq!(info.ppid, Ppid::DIAMETER);
                let cer = diameter::parse_header(&buf[..len]);
                assert!(cer.request);
                assert_eq!(cer.code, diameter::CAPABILITIES_EXCHANGE);
                let client_id = cer.hbh;
                assert_eq!(
                    diameter::find_avp(&buf[..len], diameter::ORIGIN_HOST).unwrap(),
                    format!("client{client_id}.example.com").into_bytes(),
                    "Origin-Host must belong to the client this stream accepted"
                );
                let reply = SendInfo {
                    ppid: Ppid::DIAMETER,
                    ..Default::default()
                };
                stream
                    .send_msg(&diameter::cea(cer.hbh, cer.e2e), &reply)
                    .await
                    .unwrap();

                // Serve watchdogs until the peer disconnects.
                loop {
                    match t(stream.recv_msg(&mut buf)).await.unwrap() {
                        RecvMsg::Data { len: 0, .. } => break,
                        RecvMsg::Data { len, .. } => {
                            let dwr = diameter::parse_header(&buf[..len]);
                            assert!(dwr.request);
                            assert_eq!(dwr.code, diameter::DEVICE_WATCHDOG);
                            stream
                                .send_msg(&diameter::dwa(dwr.hbh, dwr.e2e), &reply)
                                .await
                                .unwrap();
                        }
                        RecvMsg::Notification(_) => {}
                    }
                }
                if client_id == 0 {
                    let _ = gone_tx.send(()).await;
                }
                client_id
            }));
        }
        let mut ids = Vec::new();
        for h in handlers {
            ids.push(h.await.unwrap());
        }
        ids.sort_unstable();
        ids
    });

    let mut clients = Vec::new();
    for i in 0..N {
        let mut go_rx = go_tx.subscribe();
        clients.push(tokio::spawn(async move {
            let stream = t(SctpStream::connect(server_addr)).await.unwrap();
            let host = format!("client{i}.example.com");
            let info = SendInfo {
                ppid: Ppid::DIAMETER,
                ..Default::default()
            };
            stream
                .send_msg(&diameter::cer(&host, i, 0x5000 + i), &info)
                .await
                .unwrap();

            let mut buf = vec![0u8; 4096];
            let (len, rcv) = recv_data(&stream, &mut buf).await;
            assert_eq!(rcv.ppid, Ppid::DIAMETER);
            let cea = diameter::parse_header(&buf[..len]);
            assert!(!cea.request);
            assert_eq!(cea.code, diameter::CAPABILITIES_EXCHANGE);
            // RFC 6733: answers echo the request's identifiers. This is also
            // the isolation check — an answer meant for another client would
            // carry a different hop-by-hop id.
            assert_eq!(cea.hbh, i);
            assert_eq!(cea.e2e, 0x5000 + i);
            assert_eq!(
                diameter::result_code(&buf[..len]),
                Some(diameter::DIAMETER_SUCCESS)
            );

            if i == 0 {
                // The first client leaves; the rest must be unaffected.
                stream.shutdown(Shutdown::Write).unwrap();
                return;
            }
            // Wait until the server has fully processed client 0's
            // departure, then verify this association still works.
            t(go_rx.recv()).await.unwrap();
            stream
                .send_msg(&diameter::dwr(&host, 0x100 + i, 0x6000 + i), &info)
                .await
                .unwrap();
            let (len, _) = recv_data(&stream, &mut buf).await;
            let dwa = diameter::parse_header(&buf[..len]);
            assert!(!dwa.request);
            assert_eq!(dwa.code, diameter::DEVICE_WATCHDOG);
            assert_eq!((dwa.hbh, dwa.e2e), (0x100 + i, 0x6000 + i));
            assert_eq!(
                diameter::result_code(&buf[..len]),
                Some(diameter::DIAMETER_SUCCESS)
            );
        }));
    }

    // Release the survivors once client 0's stream is gone server-side.
    t(gone_rx.recv()).await.unwrap();
    go_tx.send(()).unwrap();

    for c in clients {
        c.await.unwrap();
    }
    // All N clients were served, each by its own accepted stream.
    assert_eq!(server.await.unwrap(), (0..N).collect::<Vec<_>>());
}

/// Per-stream ordering metadata: SSN increments per sid, and UNORDERED
/// messages carry the unordered flag with no SSN sequencing.
#[tokio::test]
async fn ssn_ordering_and_unordered_flag() {
    if !sctp_available() {
        return;
    }

    let listener = SctpListener::builder(Family::Ipv4)
        .unwrap()
        .init_params(&InitParams {
            num_ostreams: 4,
            max_instreams: 4,
            ..Default::default()
        })
        .unwrap()
        .bindx(&[localhost(0)])
        .unwrap()
        .listen(8)
        .unwrap();
    let server_addr = listener.local_addr().unwrap();

    let client_task = tokio::spawn(async move {
        let stream = SctpStream::builder(Family::Ipv4)
            .unwrap()
            .init_params(&InitParams {
                num_ostreams: 4,
                max_instreams: 4,
                ..Default::default()
            })
            .unwrap()
            .connectx(&[server_addr])
            .await
            .unwrap();
        // Three ordered M3UA heartbeats on each of sid 0 and sid 1,
        // interleaved, then one unordered heartbeat on sid 0. The Heartbeat
        // Data parameter carries (sid, seq) so the receiver can check
        // delivery against what was sent.
        for n in 0..3u8 {
            for sid in [0u16, 1u16] {
                let info = SendInfo {
                    sid,
                    ppid: Ppid::M3UA,
                    ..Default::default()
                };
                stream
                    .send_msg(&m3ua::beat(&[sid as u8, n]), &info)
                    .await
                    .unwrap();
            }
        }
        let info = SendInfo {
            sid: 0,
            ppid: Ppid::M3UA,
            flags: SendFlags::UNORDERED,
            ..Default::default()
        };
        stream
            .send_msg(&m3ua::beat(b"unordered"), &info)
            .await
            .unwrap();
    });

    let (stream, _) = t(listener.accept()).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let mut ssns: std::collections::HashMap<u16, Vec<u16>> = std::collections::HashMap::new();
    let mut tsns: Vec<u32> = Vec::new();
    let mut saw_unordered = false;
    while !saw_unordered {
        match t(stream.recv_msg(&mut buf)).await.unwrap() {
            RecvMsg::Data { len, info, eor } => {
                assert!(eor);
                let info = info.unwrap();
                if info.flags.unordered() {
                    assert_eq!(&buf[..len], &m3ua::beat(b"unordered")[..]);
                    assert_eq!(info.sid, 0);
                    // Unordered messages carry no stream sequence number.
                    assert_eq!(info.ssn, 0);
                    saw_unordered = true;
                } else {
                    let seq = ssns.entry(info.sid).or_default();
                    let expected = m3ua::beat(&[info.sid as u8, seq.len() as u8]);
                    assert_eq!(&buf[..len], &expected[..]);
                    seq.push(info.ssn);
                    tsns.push(info.tsn);
                }
            }
            other => panic!("expected data, got {other:?}"),
        }
    }

    // Ordered messages: SSN counts 0, 1, 2 independently per stream id.
    assert_eq!(ssns[&0], vec![0, 1, 2]);
    assert_eq!(ssns[&1], vec![0, 1, 2]);
    // TSNs are assigned in send order across the association.
    assert!(
        tsns.windows(2).all(|w| w[0] < w[1]),
        "TSNs not increasing: {tsns:?}"
    );

    client_task.await.unwrap();
}

/// Async connect to a closed port must fail (via the CantStartAssoc
/// notification path), not resolve successfully mid-handshake.
#[tokio::test]
async fn connect_refused() {
    if !sctp_available() {
        return;
    }

    // Grab a port that is guaranteed closed by binding and dropping.
    let probe = SctpSocket::new(Family::Ipv4, Style::OneToOne).unwrap();
    probe.bind(&localhost(0)).unwrap();
    let dead_addr = probe.local_addr().unwrap();
    drop(probe);

    let err = t(SctpStream::connect(dead_addr))
        .await
        .expect_err("connect to a closed port must fail");
    assert!(
        err.kind() == std::io::ErrorKind::ConnectionRefused
            || err.raw_os_error() == Some(libc_econnrefused()),
        "unexpected error: {err:?}"
    );
}

fn libc_econnrefused() -> i32 {
    111 // ECONNREFUSED on Linux
}

/// IPv6 works end to end: one-to-one echo over ::1.
#[tokio::test]
async fn ipv6_one_to_one_echo() {
    if !sctp_available() || !common::sctp_ipv6_available() {
        return;
    }

    let listener = match SctpListener::bind("[::1]:0".parse().unwrap()) {
        Ok(l) => l,
        // No IPv6 loopback in this environment (e.g. ipv6.disable=1).
        Err(e) => {
            eprintln!("skipping: cannot bind ::1 ({e})");
            return;
        }
    };
    let server_addr = listener.local_addr().unwrap();
    assert!(server_addr.is_ipv6());

    let client_task = tokio::spawn(async move {
        let stream = t(SctpStream::connect(server_addr)).await.unwrap();
        let info = SendInfo {
            ppid: Ppid::DIAMETER,
            ..Default::default()
        };
        stream
            .send_msg(&diameter::cer("v6.example.com", 9, 0x90), &info)
            .await
            .unwrap();
        let mut buf = vec![0u8; 4096];
        let (len, _) = recv_data(&stream, &mut buf).await;
        let cea = diameter::parse_header(&buf[..len]);
        assert_eq!((cea.hbh, cea.e2e), (9, 0x90));
    });

    let (stream, peer) = t(listener.accept()).await.unwrap();
    assert!(peer.is_ipv6());
    let mut buf = vec![0u8; 4096];
    let (len, _) = recv_data(&stream, &mut buf).await;
    let cer = diameter::parse_header(&buf[..len]);
    assert_eq!(
        diameter::find_avp(&buf[..len], diameter::ORIGIN_HOST).unwrap(),
        b"v6.example.com"
    );
    stream
        .send_msg(
            &diameter::cea(cer.hbh, cer.e2e),
            &SendInfo {
                ppid: Ppid::DIAMETER,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    client_task.await.unwrap();
}
