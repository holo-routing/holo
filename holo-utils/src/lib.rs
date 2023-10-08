//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

#![warn(rust_2018_idioms)]
#![feature(ip)]
#![cfg_attr(
    feature = "testing",
    allow(dead_code, unused_variables, unused_imports)
)]

use std::sync::{Arc, Mutex};

use pickledb::PickleDb;

pub mod bfd;
pub mod bytes;
pub mod capabilities;
pub mod crypto;
pub mod ibus;
pub mod ip;
pub mod keychain;
pub mod mpls;
pub mod policy;
pub mod protocol;
pub mod socket;
pub mod sr;
pub mod task;
pub mod yang;

pub type Sender<T> = tokio::sync::mpsc::Sender<T>;
pub type Receiver<T> = tokio::sync::mpsc::Receiver<T>;
pub type Responder<T> = tokio::sync::oneshot::Sender<T>;
pub type UnboundedSender<T> = tokio::sync::mpsc::UnboundedSender<T>;
pub type UnboundedReceiver<T> = tokio::sync::mpsc::UnboundedReceiver<T>;

pub type Database = Arc<Mutex<PickleDb>>;
pub type DatabaseError = pickledb::error::Error;
