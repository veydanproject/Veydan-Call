//! The little of SDP text the SFU reads itself: str0m parses the rest.
//!
//! In RTP mode str0m sends on a stream only after `declare_stream_tx` with
//! the SSRC it announced in the SDP for that m-line (`a=ssrc:`, or the
//! pair of `a=ssrc-group:FID` when there is a repair stream), and the SDP
//! text is where that number is. The ICE ufrag is read off an offer or
//! answer the same way, to route a first STUN packet to its room.

/// The SSRCs str0m announced for `mid` in `sdp`: the main one and, for
/// video, the RTX one. `None` when the m-line announces none.
pub fn ssrcs_of(sdp: &str, mid: &str) -> Option<(u32, Option<u32>)> {
    let section = section_of(sdp, mid)?;
    let mut main = None;
    let mut rtx = None;
    for line in section {
        if let Some(group) = line.strip_prefix("a=ssrc-group:FID ") {
            let mut parts = group.split_whitespace().filter_map(|n| n.parse::<u32>().ok());
            main = parts.next();
            rtx = parts.next();
            break;
        }
        if main.is_none() {
            if let Some(rest) = line.strip_prefix("a=ssrc:") {
                main = rest.split(' ').next().and_then(|n| n.parse().ok());
            }
        }
    }
    main.map(|m| (m, rtx))
}

/// Every SSRC pair str0m announced for `mid`, in the order of the
/// m-line's `a=ssrc-group:FID` lines: with simulcast, one pair a layer in
/// the order of the rids. An m-line without FID groups gives its single
/// `a=ssrc`, if any.
pub fn ssrc_groups_of(sdp: &str, mid: &str) -> Vec<(u32, Option<u32>)> {
    let Some(section) = section_of(sdp, mid) else {
        return Vec::new();
    };
    let groups: Vec<(u32, Option<u32>)> = section
        .iter()
        .filter_map(|line| line.strip_prefix("a=ssrc-group:FID "))
        .filter_map(|group| {
            let mut parts = group.split_whitespace().filter_map(|n| n.parse::<u32>().ok());
            parts.next().map(|main| (main, parts.next()))
        })
        .collect();
    if !groups.is_empty() {
        return groups;
    }
    ssrcs_of(sdp, mid).into_iter().collect()
}

/// The ICE ufrag of `sdp`: of the session, or of the first m-line that
/// names one.
pub fn ufrag_of(sdp: &str) -> Option<&str> {
    sdp.lines().find_map(|l| l.strip_prefix("a=ice-ufrag:")).map(str::trim)
}

/// The ICE credentials of `sdp`, ufrag and password, the same way.
pub fn ice_credentials(sdp: &str) -> Option<(String, String)> {
    let ufrag = ufrag_of(sdp)?;
    let pwd = sdp.lines().find_map(|l| l.strip_prefix("a=ice-pwd:")).map(str::trim)?;
    Some((ufrag.to_string(), pwd.to_string()))
}

/// How many audio and video m-lines `sdp` declares.
pub fn media_lines(sdp: &str) -> usize {
    sdp.lines().filter(|l| l.starts_with("m=audio ") || l.starts_with("m=video ")).count()
}

/// The audio budget of a participant's `kbps`, and what is left for
/// video: Opus needs little, the rest is video with a margin for the RTP
/// headers that the node's bucket counts and an encoder does not.
const AUDIO_KBPS: u32 = 128;
const VIDEO_MIN_KBPS: u32 = 50;
const HEADER_MARGIN_PERCENT: u32 = 5;
pub fn media_budget(kbps: u32) -> (u32, u32) {
    let audio = kbps.min(AUDIO_KBPS);
    let video = (kbps.saturating_sub(audio) * (100 - HEADER_MARGIN_PERCENT) / 100).max(VIDEO_MIN_KBPS);
    (audio, video)
}

/// `sdp` with a bandwidth line (`b=AS:`, kbit/s, RFC 4566 5.8) in every
/// audio and video m-section, after its `c=` line: what the node will
/// take on that m-line. libwebrtc caps its encoder at the `b=AS` of the
/// remote description, so a participant told this way stays under the
/// node's bucket instead of losing packets to it in silence. `kbps` 0:
/// no limit of the node's.
pub fn with_bandwidth(sdp: &str, kbps: u32) -> String {
    with_bandwidth_capped(sdp, kbps, &[])
}

/// [`with_bandwidth`] with a cap for each audio and video m-section in
/// order (the `b=AS` of another node's answer on the same m-line, in the
/// cascade): the lower of the two goes in, and a cap alone when the node
/// has no limit. A section with neither gets no line.
pub fn with_bandwidth_capped(sdp: &str, kbps: u32, caps: &[Option<u32>]) -> String {
    let (audio, video) = media_budget(kbps);
    let mut out = String::with_capacity(sdp.len() + 64);
    let mut budget: Option<u32> = None;
    let mut ending = "\r\n";
    let mut section = 0usize;
    for line in sdp.split_inclusive('\n') {
        let bare = line.trim_end();
        ending = if line.ends_with("\r\n") { "\r\n" } else { "\n" };
        if bare.starts_with("m=") {
            // A section that had no c= line gets its b= at its end.
            if let Some(kbps) = budget.take() {
                out.push_str(&format!("b=AS:{kbps}{ending}"));
            }
            let own = match bare.split(' ').next() {
                Some("m=audio") => Some(audio),
                Some("m=video") => Some(video),
                _ => None,
            };
            budget = match own {
                Some(own) => {
                    let cap = caps.get(section).copied().flatten();
                    section += 1;
                    match (kbps > 0, cap) {
                        (true, Some(cap)) => Some(own.min(cap)),
                        (true, None) => Some(own),
                        (false, cap) => cap,
                    }
                }
                None => None,
            };
        }
        out.push_str(line);
        if bare.starts_with("c=") {
            if let Some(kbps) = budget.take() {
                out.push_str(&format!("b=AS:{kbps}{ending}"));
            }
        }
    }
    if let Some(kbps) = budget {
        out.push_str(&format!("b=AS:{kbps}{ending}"));
    }
    out
}

/// The `b=AS:` of each audio and video m-section of `sdp`, in order;
/// `None` where a section has none.
pub fn bandwidth_of(sdp: &str) -> Vec<Option<u32>> {
    let mut out = Vec::new();
    for section in sections(sdp) {
        let Some(first) = section.first() else { continue };
        if !(first.starts_with("m=audio ") || first.starts_with("m=video ")) {
            continue;
        }
        out.push(section.iter().find_map(|l| l.strip_prefix("b=AS:")).and_then(|n| n.trim().parse().ok()));
    }
    out
}

/// One audio or video m-section of an offer, as the cascade mirrors it:
/// its mid, its kind and the simulcast rids it sends (in the order
/// declared; empty for one stream).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaSection {
    pub mid: String,
    pub kind: str0m::media::MediaKind,
    pub rids: Vec<String>,
}

/// The audio and video m-sections of `sdp`, in order. A section without
/// a mid is left out.
pub fn media_sections(sdp: &str) -> Vec<MediaSection> {
    let mut out = Vec::new();
    for section in sections(sdp) {
        let Some(first) = section.first() else { continue };
        let kind = if first.starts_with("m=audio ") {
            str0m::media::MediaKind::Audio
        } else if first.starts_with("m=video ") {
            str0m::media::MediaKind::Video
        } else {
            continue;
        };
        let Some(mid) = section.iter().find_map(|l| l.strip_prefix("a=mid:")).map(|m| m.trim().to_string()) else { continue };
        // `a=rid:q send ...` lines, in the order of `a=simulcast:send q;h;f`
        // when there is one, else as declared.
        let declared: Vec<String> = section
            .iter()
            .filter_map(|l| l.strip_prefix("a=rid:"))
            .filter_map(|rest| {
                let mut parts = rest.split_whitespace();
                let rid = parts.next()?;
                (parts.next() == Some("send")).then(|| rid.to_string())
            })
            .collect();
        let rids = match section.iter().find_map(|l| l.strip_prefix("a=simulcast:send ")) {
            Some(list) => list
                .split(';')
                .map(|r| r.trim().trim_start_matches('~').split(',').next().unwrap_or("").to_string())
                .filter(|r| declared.contains(r))
                .collect(),
            None => declared,
        };
        out.push(MediaSection { mid, kind, rids });
    }
    out
}

/// The mids of the m-sections `sdp` closes: port 0, or `a=inactive`.
pub fn stopped_mids(sdp: &str) -> Vec<String> {
    let mut out = Vec::new();
    for section in sections(sdp) {
        let Some(first) = section.first() else { continue };
        let port_zero = first.split_whitespace().nth(1) == Some("0");
        let inactive = section.contains(&"a=inactive");
        if !(port_zero || inactive) {
            continue;
        }
        if let Some(mid) = section.iter().find_map(|l| l.strip_prefix("a=mid:")) {
            out.push(mid.trim().to_string());
        }
    }
    out
}

/// `sdp` with only the candidates `keep` takes: an `a=candidate:` line
/// names its transport and address (RFC 8839 5.1), and `keep` is asked
/// with both. How many were kept is returned with it.
pub fn keep_candidates(sdp: &str, mut keep: impl FnMut(&str, std::net::IpAddr) -> bool) -> (String, usize) {
    let mut out = String::with_capacity(sdp.len());
    let mut kept = 0;
    for line in sdp.split_inclusive('\n') {
        let bare = line.trim_end();
        if let Some(rest) = bare.strip_prefix("a=candidate:") {
            // foundation component transport priority address port typ ...
            let mut parts = rest.split_whitespace();
            let transport = parts.nth(2).unwrap_or("").to_ascii_lowercase();
            let address = parts.nth(1).and_then(|a| a.parse::<std::net::IpAddr>().ok());
            match address {
                Some(ip) if keep(&transport, ip) => kept += 1,
                _ => continue,
            }
        }
        out.push_str(line);
    }
    (out, kept)
}

/// The m-sections of `sdp`, each as its lines.
fn sections(sdp: &str) -> Vec<Vec<&str>> {
    let mut sections: Vec<Vec<&str>> = Vec::new();
    for line in sdp.lines().map(str::trim_end) {
        if line.starts_with("m=") {
            sections.push(Vec::new());
        }
        if let Some(last) = sections.last_mut() {
            last.push(line);
        }
    }
    sections
}

/// The lines of the m-section carrying `a=mid:<mid>`.
fn section_of<'a>(sdp: &'a str, mid: &str) -> Option<Vec<&'a str>> {
    sections(sdp).into_iter().find(|s| s.iter().any(|l| l.strip_prefix("a=mid:").is_some_and(|m| m.trim() == mid)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SDP: &str = "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\na=ice-ufrag:abcd\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:0\r\na=ssrc:1111 cname:x\r\nm=video 9 UDP/TLS/RTP/SAVPF 96 97\r\na=mid:1\r\na=ssrc-group:FID 2222 3333\r\na=ssrc:2222 cname:y\r\na=ssrc:3333 cname:y\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=mid:2\r\n";

    #[test]
    fn ssrcs_and_ufrag_are_read() {
        assert_eq!(ssrcs_of(SDP, "0"), Some((1111, None)));
        assert_eq!(ssrcs_of(SDP, "1"), Some((2222, Some(3333))));
        assert_eq!(ssrcs_of(SDP, "2"), None);
        assert_eq!(ssrcs_of(SDP, "9"), None);
        assert_eq!(ssrc_groups_of(SDP, "0"), vec![(1111, None)]);
        assert_eq!(ssrc_groups_of(SDP, "1"), vec![(2222, Some(3333))]);
        assert_eq!(ssrc_groups_of(SDP, "2"), vec![]);
        let layers = "m=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:1\r\na=ssrc-group:FID 10 11\r\na=ssrc-group:FID 20 21\r\na=ssrc-group:FID 30 31\r\na=ssrc:10 cname:y\r\n";
        assert_eq!(ssrc_groups_of(layers, "1"), vec![(10, Some(11)), (20, Some(21)), (30, Some(31))], "one pair a layer, in order");
        assert_eq!(ufrag_of(SDP), Some("abcd"));
        assert_eq!(ufrag_of("v=0\r\n"), None);
        assert_eq!(ice_credentials("v=0\r\na=ice-ufrag:u1\r\na=ice-pwd:p1\r\n"), Some(("u1".into(), "p1".into())));
        assert_eq!(ice_credentials(SDP), None);
        assert_eq!(media_lines(SDP), 2);
        assert_eq!(media_lines("v=0\r\n"), 0);
    }

    #[test]
    fn a_bandwidth_line_goes_into_every_media_section() {
        let sdp = "v=0\r\nc=IN IP4 0.0.0.0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\nc=IN IP4 0.0.0.0\r\na=mid:0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:1\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\na=mid:2\r\n";
        let out = with_bandwidth(sdp, 2500);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[1], "c=IN IP4 0.0.0.0", "the session's c= gets none");
        assert_eq!(lines[3..5], ["c=IN IP4 0.0.0.0", "b=AS:128"], "{out}");
        // No c= in the video section: at its end, before the next m=.
        assert_eq!(lines[7..9], ["a=mid:1", "b=AS:2253"], "{out}");
        assert!(!lines[9..].iter().any(|l| l.starts_with("b=")), "the data channel gets none: {out}");
        assert_eq!(out.matches("b=AS:").count(), 2);
        assert_eq!(media_budget(2500), (128, 2253));
        assert_eq!(media_budget(100), (100, 50));
        assert_eq!(with_bandwidth("v=0\n", 100), "v=0\n");
        // Capped by another node's answer: the lower of the two; the cap
        // alone when this node has no limit; nothing without either.
        let capped = with_bandwidth_capped(sdp, 2500, &[Some(64), Some(9000)]);
        assert_eq!(bandwidth_of(&capped), vec![Some(64), Some(2253)]);
        assert_eq!(bandwidth_of(&with_bandwidth_capped(sdp, 0, &[None, Some(700)])), vec![None, Some(700)]);
        assert_eq!(bandwidth_of(&with_bandwidth_capped(sdp, 0, &[])), vec![None, None]);
        assert_eq!(bandwidth_of(sdp), vec![None, None]);
    }

    #[test]
    fn an_offer_is_read_for_the_cascade() {
        let sdp = "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:0\r\na=sendonly\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:1\r\na=rid:q send\r\na=rid:h send\r\na=rid:f send\r\na=simulcast:send q;h;f\r\nm=video 0 UDP/TLS/RTP/SAVPF 96\r\na=mid:2\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=mid:3\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:4\r\na=inactive\r\n";
        let sections = media_sections(sdp);
        assert_eq!(sections.len(), 4);
        assert_eq!((sections[0].mid.as_str(), sections[0].kind, sections[0].rids.len()), ("0", str0m::media::MediaKind::Audio, 0));
        assert_eq!((sections[1].mid.as_str(), sections[1].kind), ("1", str0m::media::MediaKind::Video));
        assert_eq!(sections[1].rids, vec!["q", "h", "f"]);
        assert_eq!(stopped_mids(sdp), vec!["2", "4"]);
        // Rids as declared when there is no simulcast line, in their order.
        let plain = "m=video 9 X\r\na=mid:1\r\na=rid:h send\r\na=rid:q send\r\n";
        assert_eq!(media_sections(plain)[0].rids, vec!["h", "q"]);
    }

    #[test]
    fn candidates_are_kept_by_transport_and_address() {
        let sdp = "v=0\r\nm=audio 9 X\r\na=mid:0\r\na=candidate:1 1 udp 2130706431 203.0.113.7 3479 typ host\r\na=candidate:2 1 TCP 1 203.0.113.7 3479 typ host tcptype passive\r\na=candidate:3 1 udp 1 10.0.0.1 3479 typ host\r\na=candidate:bad\r\na=end-of-candidates\r\n";
        let home: std::net::IpAddr = "203.0.113.7".parse().unwrap();
        let (kept, n) = keep_candidates(sdp, |transport, ip| transport == "udp" && ip == home);
        assert_eq!(n, 1);
        assert_eq!(kept.matches("a=candidate:").count(), 1, "{kept}");
        assert!(kept.contains("203.0.113.7 3479 typ host\r\n"));
        assert!(kept.contains("a=end-of-candidates"), "other lines stay");
        let (none, n) = keep_candidates(sdp, |_, _| false);
        assert_eq!((n, none.matches("a=candidate:").count()), (0, 0));
    }
}
