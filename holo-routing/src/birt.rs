//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeMap, BTreeSet};

use holo_utils::bier::{
    self, BfrId, Bift, BirtEntry, Bitstring, Bsl, SubDomainId,
};
use holo_utils::southbound::{BierNbrInstallMsg, BierNbrUninstallMsg, Nexthop};
use tokio::sync::mpsc::UnboundedSender;

use crate::interface::Interfaces;

#[derive(Debug)]
pub struct Birt {
    pub entries: BTreeMap<(SubDomainId, BfrId, Bsl), BirtEntry>,
    pub bier_update_queue: BTreeSet<BfrId>,
    pub update_queue_tx: UnboundedSender<()>,
}

// ===== impl Birt =====

impl Birt {
    pub(crate) fn new(update_queue_tx: UnboundedSender<()>) -> Self {
        Self {
            entries: Default::default(),
            bier_update_queue: Default::default(),
            update_queue_tx,
        }
    }

    pub(crate) fn bier_nbr_add(&mut self, msg: BierNbrInstallMsg) {
        let bfr_id = msg.bier_info.bfr_id;
        msg.bier_info.bfr_bss.iter().for_each(|bsl| {
            if let Some(nexthop) = msg.nexthops.last()
                && let Nexthop::Address { addr, ifindex, .. } = nexthop
            {
                // Insert or update the entry in the BIRT
                self.entries
                    .entry((msg.bier_info.sd_id, bfr_id, *bsl))
                    .and_modify(|be| {
                        be.bfr_nbr = *addr;
                        be.ifindex = *ifindex;
                    })
                    .or_insert(BirtEntry {
                        bfr_prefix: msg.prefix.ip(),
                        bfr_nbr: (*addr),
                        ifindex: *ifindex,
                    });

                // Add BIER route to the update queue
                self.bier_update_queue_add(bfr_id);
            }
        });
    }

    pub(crate) fn bier_nbr_del(&mut self, msg: BierNbrUninstallMsg) {
        let _ = self.entries.remove(&(msg.sd_id, msg.bfr_id, msg.bsl));
    }

    pub(crate) fn process_birt_update_queue(
        &mut self,
        interfaces: &Interfaces,
    ) {
        let mut bift = Bift::new();

        // Compute Forwarding BitMasks (F-BMs)
        for ((sd_id, bfr_id, bsl), nbr) in &self.entries {
            match Bitstring::from(*bfr_id, *bsl) {
                Ok(bfr_bs) => {
                    let ifname = interfaces
                        .iter()
                        .filter_map(|iface| {
                            if iface.ifindex == nbr.ifindex {
                                Some(iface.name.clone())
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<String>>();
                    // Pattern matching is mandatory as Bitstring does not implement Copy, hence cannot use Entry interface
                    let key = (*sd_id, nbr.bfr_nbr, bfr_bs.si);
                    match bift.get_mut(&key) {
                        Some((bitstring, bfrs, _ifindex, _ifname)) => {
                            match bitstring.mut_or(bfr_bs) {
                                Ok(()) => {
                                    bfrs.push((*bfr_id, nbr.bfr_prefix));
                                }
                                Err(e) => {
                                    e.log();
                                }
                            }
                        }
                        None => {
                            let _ = bift.insert(
                                key,
                                (
                                    bfr_bs,
                                    vec![(*bfr_id, nbr.bfr_prefix)],
                                    nbr.ifindex,
                                    ifname.first().unwrap().to_owned(),
                                ),
                            );
                        }
                    }
                }
                Err(e) => {
                    e.log();
                }
            }
        }

        bier::bift_sync(bift.clone());
    }

    // Adds BIER route to the update queue.
    fn bier_update_queue_add(&mut self, bfr_id: BfrId) {
        self.bier_update_queue.insert(bfr_id);
        let _ = self.update_queue_tx.send(());
    }
}
