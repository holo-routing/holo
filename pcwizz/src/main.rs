use holo_bgp::instance::Instance as BgpInstance;
use holo_protocol::test::setup;
use holo_protocol::test::stub::northbound::NorthboundStub;
use holo_protocol::{InstanceShared, spawn_protocol_task};
use holo_utils::ibus;
use tokio::sync::mpsc;

#[derive(Debug, Default)]
pub struct BgpManager {
    instance: Option<NorthboundStub>,
}

const CONFIG: &str = r###"
{
  "ietf-routing:routing": {
    "control-plane-protocols": {
      "control-plane-protocol": [
        {
          "type": "ietf-bgp:bgp",
          "name": "main",
          "ietf-bgp:bgp": {
            "global": {
              "as": 65001,
              "identifier": "1.1.1.1",
              "holo-bgp:trace-options": {
                "flag": [
                  {
                    "name": "route"
                  },
                  {
                    "name": "packets-all"
                  },
                  {
                    "name": "events"
                  }
                ]
              }
            },
            "neighbors": {
              "neighbor": [
                {
                  "remote-address": "10.0.1.2",
                  "peer-as": 65002,
                  "afi-safis": {
                    "afi-safi": [
                      {
                        "name": "iana-bgp-types:ipv4-unicast",
                        "enabled": true,
                        "apply-policy": {
                          "default-import-policy": "accept-route",
                          "default-export-policy": "accept-route"
                        }
                      }
                    ]
                  }
                }
              ]
            }
          }
        }
      ]
    }
  }
}"###;

impl BgpManager {
    pub async fn start_instance(
        &mut self,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Spawn protocol task.
        let (nb_tx, mut nb_rx) = mpsc::unbounded_channel();
        let ((ibus_tx, _, _, _, _), _ibus_rx) = ibus::ibus_channels();
        let (ibus_instance_tx, ibus_instance_rx) = mpsc::unbounded_channel();
        let nb_tx = spawn_protocol_task::<BgpInstance>(
            "main".to_owned(),
            &nb_tx,
            &ibus_tx,
            ibus_instance_tx,
            ibus_instance_rx,
            Default::default(),
            InstanceShared::default(),
        );

        // Spawn a task that drains northbound notifications.
        tokio::task::spawn(async move {
            while let Some(_msg) = nb_rx.recv().await {}
        });

        // Send BGP configuration.
        let mut nb_stub = NorthboundStub::new(nb_tx);
        nb_stub.commit_replace(CONFIG).await;

        // Store BGP instance handle.
        self.instance = Some(nb_stub);

        Ok(())
    }

    pub async fn stop_instance(&mut self) {
        self.instance = None;
    }
}

//#[unsaFE(no_mangle)]
pub extern "C" fn HonggfuzzNetDriver_main() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut bgp_manager = BgpManager::default();
        bgp_manager.start_instance().await.unwrap();
        let future = std::future::pending::<()>();
        future.await
    });
}

fn main() {
    setup();
    HonggfuzzNetDriver_main();
}
