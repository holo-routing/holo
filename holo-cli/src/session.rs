//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use derive_new::new;
use enum_as_inner::EnumAsInner;
use indextree::NodeId;
use yang2::data::{Data, DataFormat, DataTree, DataValidationFlags};
use yang2::schema::{SchemaNode, SchemaNodeKind};

use crate::client::Client;
use crate::error::Error;
use crate::parser::ParsedArgs;
use crate::token::Commands;
use crate::token_yang;

#[derive(Debug)]
pub struct Session {
    hostname: String,
    prompt: String,
    use_pager: bool,
    mode: CommandMode,
    running: DataTree,
    candidate: Option<DataTree>,
    client: Box<dyn Client>,
}

#[derive(Clone, Debug, Eq, PartialEq, EnumAsInner)]
pub enum CommandMode {
    Operational,
    Configure { nodes: Vec<CommandNode> },
}

#[derive(Clone, Debug, Eq, PartialEq, new)]
pub struct CommandNode {
    token_id: NodeId,
    cli_path: String,
    data_path: String,
}

#[derive(Clone, Copy, Debug)]
pub enum ConfigurationType {
    Running,
    Candidate,
}

// ===== impl Session =====

impl Session {
    pub(crate) fn new(
        hostname: String,
        use_pager: bool,
        mut client: Box<dyn Client>,
    ) -> Session {
        let running = client.get_running_config();

        Session {
            hostname,
            prompt: String::new(),
            use_pager,
            mode: CommandMode::Operational,
            running,
            candidate: None,
            client,
        }
    }

    pub(crate) fn update_hostname(&mut self, hostname: &str) {
        hostname.clone_into(&mut self.hostname);
        self.update_prompt();
    }

    pub(crate) fn prompt(&self) -> String {
        self.prompt.clone()
    }

    pub(crate) fn use_pager(&self) -> bool {
        self.use_pager
    }

    pub(crate) fn update_prompt(&mut self) {
        self.prompt = match &self.mode {
            CommandMode::Operational => self.hostname.clone(),
            CommandMode::Configure { nodes } => {
                let path = match nodes.last() {
                    Some(node) => &node.cli_path,
                    None => "",
                };
                format!("{}(config{})", self.hostname, path)
            }
        }
    }

    pub(crate) fn mode(&self) -> &CommandMode {
        &self.mode
    }

    pub(crate) fn mode_set(&mut self, mode: CommandMode) {
        if self.mode == mode {
            return;
        }

        // Create/delete candidate configuration if necessary.
        if mode.is_configure() && self.mode.is_operational() {
            self.candidate = Some(self.running.duplicate().unwrap());
        } else if mode.is_operational() && self.mode.is_configure() {
            self.candidate = None;
        }

        self.mode = mode;
        self.update_prompt();
    }

    fn mode_config_enter(&mut self, node: CommandNode) {
        let nodes = self.mode.as_configure_mut().unwrap();
        nodes.push(node);
        self.update_prompt();
    }

    pub(crate) fn mode_config_exit(&mut self) {
        let nodes = self.mode.as_configure_mut().unwrap();
        if nodes.pop().is_none() {
            self.mode = CommandMode::Operational
        }
        self.update_prompt();
    }

    pub(crate) fn edit_candidate(
        &mut self,
        negate: bool,
        snode: &SchemaNode<'_>,
        mut args: ParsedArgs,
    ) -> Result<(), yang2::Error> {
        // Get data path and CLI path corresponding to the current node.
        let mut path = self.mode.data_path().unwrap_or_default();
        let mut cli_path = self.mode.cli_path().unwrap_or_default();

        // Create list of schema nodes, ordered from parent to child.
        let mut snodes = vec![];
        if !snode.is_list_key() {
            snodes.extend(snode.inclusive_ancestors());
        } else {
            snodes.extend(snode.ancestors());
        }

        // Iterate over all schema nodes starting from the root.
        let mut skip = self.mode.as_configure().unwrap().len();
        for snode in snodes.iter().filter(|snode| !snode.is_schema_only()).rev()
        {
            // Ignore schema nodes above the current CLI node.
            if skip > 0 {
                if snode.kind() == SchemaNodeKind::List || snode.is_list_key() {
                    skip -= 1;
                    continue;
                }
                if skip > 0 {
                    continue;
                }
            }

            // Update data path.
            path += &format!("/{}:{}", snode.module().name(), snode.name());
            let mut list_keys = ParsedArgs::new();
            for snode in snode.list_keys() {
                let arg = args.pop_front().unwrap();
                path += &format!("[{}='{}']", snode.name(), arg.1);
                list_keys.push_back(arg);
            }

            // Update CLI node.
            if !negate
                && (snode.kind() == SchemaNodeKind::List || snode.is_list_key())
            {
                let snode = match snode.list_keys().last() {
                    Some(last_key) => last_key.clone(),
                    None => snode.clone(),
                };
                let token_id = token_yang::snode_get_token_id(&snode);
                token_yang::update_cli_path(&mut cli_path, &snode, &list_keys);
                let node =
                    CommandNode::new(token_id, cli_path.clone(), path.clone());
                self.mode_config_enter(node);
            }
        }

        // Get leaf/leaf-list's value.
        let value = match snode.kind() {
            yang2::schema::SchemaNodeKind::Leaf
            | yang2::schema::SchemaNodeKind::LeafList
                if !snode.is_list_key() =>
            {
                if let Some((_, value)) = args.pop_front() {
                    Some(value)
                } else {
                    None
                }
            }
            _ => None,
        };

        // Ensure all arguments were processed.
        assert_eq!(args.len(), 0);

        // Edit the candidate configuration.
        let candidate = self.candidate.as_mut().unwrap();
        if negate {
            if candidate.find_path(&path).is_ok() {
                candidate.remove(&path)?;
            }
        } else {
            candidate.new_path(&path, value.as_deref(), false)?;
        }

        Ok(())
    }

    pub(crate) fn candidate_discard(&mut self) {
        self.candidate = Some(self.running.duplicate().unwrap());
    }

    pub(crate) fn candidate_validate(&mut self) -> Result<(), Error> {
        let candidate = self.candidate.as_mut().unwrap();

        // Validate the candidate configuration against YANG schema first.
        Session::validate_configuration_yang(candidate)?;

        // Request the device to do a full configuration validation.
        self.client.validate_candidate(candidate)
    }

    pub(crate) fn candidate_commit(
        &mut self,
        comment: Option<String>,
    ) -> Result<(), Error> {
        let candidate = self.candidate.as_mut().unwrap();

        // Validate the candidate configuration against YANG schema first.
        Session::validate_configuration_yang(candidate)?;

        // Request the device to validate and commit the candidate
        // configuration.
        self.client
            .commit_candidate(&self.running, candidate, comment)?;

        // Replace the running configuration with the candidate configuration.
        self.running = candidate.duplicate().unwrap();

        Ok(())
    }

    fn validate_configuration_yang(config: &mut DataTree) -> Result<(), Error> {
        config
            .validate(DataValidationFlags::NO_STATE)
            .map_err(Error::ValidateConfig)
    }

    pub(crate) fn get_configuration(
        &mut self,
        config_type: ConfigurationType,
    ) -> &DataTree {
        match config_type {
            ConfigurationType::Running => &self.running,
            ConfigurationType::Candidate => self.candidate.as_ref().unwrap(),
        }
    }

    pub(crate) fn get_state(
        &mut self,
        xpath: Option<String>,
        format: DataFormat,
    ) -> Result<String, Error> {
        self.client.get_state(xpath, format)
    }
}

// ===== impl CommandMode =====

impl CommandMode {
    pub(crate) fn token(&self, commands: &Commands) -> NodeId {
        match self {
            CommandMode::Operational => commands.exec_root,
            CommandMode::Configure { nodes } => match nodes.last() {
                Some(node) => node.token_id,
                None => commands.config_root_yang,
            },
        }
    }

    pub(crate) fn cli_path(&self) -> Option<String> {
        match self {
            CommandMode::Operational => None,
            CommandMode::Configure { nodes } => {
                nodes.last().map(|node| node.cli_path.clone())
            }
        }
    }

    pub(crate) fn data_path(&self) -> Option<String> {
        match self {
            CommandMode::Operational => None,
            CommandMode::Configure { nodes } => {
                nodes.last().map(|node| node.data_path.clone())
            }
        }
    }
}
