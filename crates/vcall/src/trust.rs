//! Which other nodes this node trusts in the cascade, and where it learns
//! of them: the registry's signed list of nodes.
//!
//! ```text
//!  VCALL_CASCADE=on         any node holds seats here, within VCALL_CASCADE_SEATS_PER_NODE;
//!                           a node on the registry's list, without the quota
//!  VCALL_CASCADE=registry   nodes on the registry's list only, without the quota
//!  VCALL_CASCADE=<file>     the ids in the file only, without the quota (a private network)
//!  VCALL_CASCADE=off        no seats of other nodes, no joins through this node
//! ```
//!
//! The list comes from `GET {VCALL_REGISTRY}/v1/calls/all`, every node the
//! registry gives out, signed by the registry's list key under the VLink
//! root's delegation (`vcall_proto::list`): the same root a client checks
//! its lists of bridges and nodes against, built in here and set by
//! `VCALL_REGISTRY_ROOT` for a registry of one's own. The list is asked
//! for every few minutes and kept in a file in `VCALL_DATA`, so that a
//! node that restarts while the registry is away trusts whom it trusted,
//! as long as the list has not run out. A list that does not verify
//! changes nothing and is a line in the log. A list runs out at its
//! `expires_at` (a day, as the registry issues it) whether the node
//! restarted or not: a registry that is away for longer leaves the node
//! trusting nobody by the list, until it answers again.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use vcall_proto::list::{self, SignedList};

use crate::counters::{Bump, Counters};
use crate::sfu::CascadeMode;
use crate::turn::unix_now;

/// The VLink root's key, 32 bytes as hex: what the registry's delegation
/// is checked against (`services/link/trust/root.pub`, as the app and the
/// bridges have it).
pub const ROOT_PUB: &str = "2d048caad007db20914238719070011d5db82280570b38f786abd470eccabdca";

/// Between fetches of the list, and between attempts after a failure.
pub const LIST_EVERY: Duration = Duration::from_secs(300);
pub const LIST_RETRY: Duration = Duration::from_secs(60);
/// The file in `VCALL_DATA` the last good list is kept in.
pub const LIST_FILE: &str = "registry-nodes.json";

/// Whose seats the node takes: the mode, and the ids the registry lists.
pub struct Trust {
    mode: CascadeMode,
    listed: Mutex<Listed>,
}

/// The registry's list as the node holds it: the ids, and the time it
/// runs out, after which it names nobody.
#[derive(Default)]
struct Listed {
    ids: HashSet<String>,
    expires_at: u64,
}

impl Listed {
    fn live(&self, now: u64) -> bool {
        now < self.expires_at
    }
}

impl Trust {
    pub fn new(mode: CascadeMode) -> Self {
        Self { mode, listed: Mutex::new(Listed::default()) }
    }

    pub fn mode(&self) -> &CascadeMode {
        &self.mode
    }

    /// The node takes part in the cascade at all.
    pub fn is_on(&self) -> bool {
        self.mode.is_on()
    }

    /// The registry's list is of use: it is looked at in this mode.
    pub fn wants_list(&self) -> bool {
        matches!(self.mode, CascadeMode::On | CascadeMode::Registry)
    }

    /// May `node` hold seats here, and is it free of the quota?
    pub fn admits(&self, node: &str) -> (bool, bool) {
        match &self.mode {
            CascadeMode::On => (true, self.is_listed(node)),
            CascadeMode::Off => (false, false),
            CascadeMode::Registry => {
                let listed = self.is_listed(node);
                (listed, listed)
            }
            CascadeMode::List(ids) => {
                let listed = ids.contains(node);
                (listed, listed)
            }
        }
    }

    /// Named by the registry's list, and the list has not run out.
    pub fn is_listed(&self, node: &str) -> bool {
        let l = self.listed.lock().expect("listed");
        l.live(unix_now()) && l.ids.contains(node)
    }

    /// The registry's list, as of now: the ids it names, for good (the
    /// tests, and a list handed in by hand).
    pub fn set_listed(&self, ids: HashSet<String>) {
        self.set_listed_until(ids, u64::MAX);
    }

    /// The registry's list: the ids it names, until `expires_at`.
    pub fn set_listed_until(&self, ids: HashSet<String>, expires_at: u64) {
        *self.listed.lock().expect("listed") = Listed { ids, expires_at };
    }

    /// How many the list names, none once it has run out.
    pub fn listed_now(&self) -> usize {
        let l = self.listed.lock().expect("listed");
        if l.live(unix_now()) {
            l.ids.len()
        } else {
            0
        }
    }

    /// A list that ran out is let go of, as it would not be read after a
    /// restart; was there one that named anybody?
    pub fn drop_run_out(&self, now: u64) -> bool {
        let mut l = self.listed.lock().expect("listed");
        if l.live(now) || l.ids.is_empty() {
            return false;
        }
        *l = Listed::default();
        true
    }
}

/// Fetches the registry's list of nodes and keeps [`Trust`] at it.
pub struct ListFetcher {
    /// The registry, `https://host/vlink`.
    pub registry: String,
    /// The root the list is checked against, hex.
    pub root_hex: String,
    /// Where the last good list is kept; none for nowhere (the tests).
    pub cache: Option<PathBuf>,
    pub trust: Arc<Trust>,
    pub counters: Arc<Counters>,
}

impl ListFetcher {
    /// The list kept from last time, when it still verifies: what the
    /// node trusts until the registry answers.
    pub fn load_cache(&self) -> Option<usize> {
        let path = self.cache.as_ref()?;
        let text = std::fs::read_to_string(path).ok()?;
        match self.take(&text) {
            Ok(n) => {
                tracing::info!(nodes = n, file = %path.display(), "the registry's list of nodes, from last time");
                Some(n)
            }
            Err(e) => {
                tracing::info!(file = %path.display(), error = %e, "the kept list of nodes is not taken");
                None
            }
        }
    }

    /// The list verified and taken: how many nodes it names.
    fn take(&self, text: &str) -> anyhow::Result<usize> {
        let signed: SignedList = serde_json::from_str(text)?;
        let list = list::verify_list(&signed, &self.root_hex, unix_now())?;
        let ids: HashSet<String> = list.nodes.iter().filter_map(|n| n.id()).map(|id| id.to_ascii_lowercase()).collect();
        let n = ids.len();
        self.trust.set_listed_until(ids, list.expires_at);
        Ok(n)
    }

    /// One fetch: the list asked for, verified, taken and kept.
    pub async fn refresh(&self) -> anyhow::Result<usize> {
        let url = format!("{}/v1/calls/all", self.registry.trim_end_matches('/'));
        let answer = crate::https::get(&url).await?;
        anyhow::ensure!(answer.status == 200, "{} {}", answer.status, answer.text());
        let text = String::from_utf8(answer.body)?;
        let n = self.take(&text)?;
        if let Some(path) = &self.cache {
            if let Err(e) = write_private(path, &text) {
                tracing::warn!(file = %path.display(), error = %e, "the list of nodes could not be kept");
            }
        }
        Ok(n)
    }

    /// Fetches for as long as the node runs.
    pub async fn run(self) {
        self.load_cache();
        tokio::time::sleep(Duration::from_secs(1)).await;
        let mut last: Option<usize> = None;
        loop {
            let wait = match self.refresh().await {
                Ok(n) => {
                    self.counters.trust_list_refreshed.bump();
                    if last != Some(n) {
                        tracing::info!(registry = %self.registry, nodes = n, "the registry's list of nodes");
                        last = Some(n);
                    }
                    LIST_EVERY
                }
                Err(e) => {
                    self.counters.trust_list_failed.bump();
                    tracing::warn!(registry = %self.registry, error = %format!("{e:#}"), "the registry's list of nodes was not taken");
                    if self.trust.drop_run_out(unix_now()) {
                        tracing::warn!(registry = %self.registry, "the registry's list of nodes ran out; it names nobody until the registry answers");
                        last = Some(0);
                    }
                    LIST_RETRY
                }
            };
            tokio::time::sleep(wait).await;
        }
    }
}

/// `text` written to `path` whole or not at all, for the owner.
pub(crate) fn write_private(path: &std::path::Path, text: &str) -> anyhow::Result<()> {
    let tmp = path.with_extension("tmp");
    crate::identity::write_private(&tmp, text)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_modes_admit_whom_they_say() {
        let x = "x".to_string();
        let on = Trust::new(CascadeMode::On);
        assert_eq!(on.admits("x"), (true, false));
        on.set_listed([x.clone()].into_iter().collect());
        assert_eq!(on.admits("x"), (true, true));
        assert_eq!(on.admits("y"), (true, false));
        assert!(on.wants_list() && on.is_on());
        let registry = Trust::new(CascadeMode::Registry);
        assert_eq!(registry.admits("x"), (false, false));
        registry.set_listed([x.clone()].into_iter().collect());
        assert_eq!(registry.admits("x"), (true, true));
        assert_eq!(registry.admits("y"), (false, false));
        assert_eq!(registry.listed_now(), 1);
        let file = Trust::new(CascadeMode::List([x.clone()].into_iter().collect()));
        file.set_listed(["y".to_string()].into_iter().collect());
        assert_eq!(file.admits("x"), (true, true));
        assert_eq!(file.admits("y"), (false, false), "the file is the whole list");
        assert!(!file.wants_list() && file.is_on());
        let off = Trust::new(CascadeMode::Off);
        assert_eq!(off.admits("x"), (false, false));
        assert!(!off.is_on() && !off.wants_list());
        assert_eq!(ROOT_PUB.len(), 64);
    }

    /// The list names its nodes until its `expires_at`, in memory as in
    /// the file: a registry away for longer than that leaves the node
    /// trusting nobody by the list, the same whether it restarted or not.
    #[test]
    fn a_list_that_ran_out_names_nobody() {
        let now = unix_now();
        let ids = || ["x".to_string()].into_iter().collect::<HashSet<_>>();
        let on = Trust::new(CascadeMode::On);
        on.set_listed_until(ids(), now + 60);
        assert_eq!(on.admits("x"), (true, true));
        assert_eq!(on.listed_now(), 1);
        assert!(!on.drop_run_out(now), "a live list stays");
        assert_eq!(on.listed_now(), 1);
        // Run out: the quota is back, and the count says nobody.
        on.set_listed_until(ids(), now);
        assert_eq!(on.admits("x"), (true, false));
        assert!(!on.is_listed("x"));
        assert_eq!(on.listed_now(), 0);
        // In registry mode, no seat at all.
        let registry = Trust::new(CascadeMode::Registry);
        registry.set_listed_until(ids(), now - 1);
        assert_eq!(registry.admits("x"), (false, false));
        assert!(registry.drop_run_out(now), "there was a list, run out");
        assert!(!registry.drop_run_out(now), "and now there is none");
        assert_eq!(registry.admits("x"), (false, false));
        // A fresh list afterwards is taken as before.
        registry.set_listed_until(ids(), now + 60);
        assert_eq!(registry.admits("x"), (true, true));
        // The plain setter is for good.
        let forever = Trust::new(CascadeMode::On);
        forever.set_listed(ids());
        assert_eq!(forever.admits("x"), (true, true));
        assert!(!forever.drop_run_out(u64::MAX - 1));
    }
}
