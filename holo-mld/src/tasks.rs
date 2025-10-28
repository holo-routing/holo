pub mod messages {

    use std::marker::PhantomData;

    use serde::{Deserialize, Serialize};

    use crate::version::Version;

    pub type ProtocolInputMsg<V> = input::ProtocolMsg<V>;
    pub type ProtocolOutputMsg<V> = output::ProtocolMsg<V>;

    pub mod input {

        use super::*;

        #[derive(Debug, Serialize, Deserialize)]
        pub enum ProtocolMsg<V: Version> {
            _Phantom(PhantomData<V>),
        }
    }

    pub mod output {

        use super::*;

        #[derive(Debug, Serialize, Deserialize)]
        pub enum ProtocolMsg<V: Version> {
            _Phantom(PhantomData<V>),
        }
    }
}
