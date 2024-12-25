use std::{thread, vec};

use anyhow::anyhow;
use iptables::IPTables;
use lazy_static::lazy_static;
use regex::Regex;

use crate::config::{Event, ProxySettingsConfig, Target};

const CHAIN_BETA: &str = "BETA";
const CHAIN_PREROUTING: &str = "PREROUTING";

lazy_static! {
    pub static ref REGEX_RULE_BETA: Regex = Regex::new(
        r"-A BETA -p tcp -m tcp --dport (?P<port_from>\d{1,5}) -j REDIRECT --to-ports (?P<port_to>\d{1,5})").unwrap();
    pub static ref REGEX_RULE_PREROUTING: Regex = Regex::new(
        r"-A PREROUTING -p tcp -m tcp --dport (?P<port_from>\d{1,5}) -j BETA").unwrap();
}

pub struct Manager {
    iptables: IPTables,
}

impl Manager {
    pub fn new() -> Result<Self, anyhow::Error> {
        Ok(Manager {
            iptables: iptables::new(false).map_err(|e| anyhow!("{e}"))?,
        })
    }

    pub fn watch_for_proxy_settings(
        self,
        proxy_port: u32,
        config: ProxySettingsConfig,
    ) -> Result<(), anyhow::Error> {
        self.add_beta_chain()
            .map_err(|e| anyhow!("add_beta_chain: {e}"))?;

        thread::spawn(move || loop {
            match config.recv() {
                Ok(event) => match event {
                    Event::TargetsModify => {
                        let targets: &Vec<Target> = &config.targets();

                        match self.process(proxy_port, targets) {
                            Ok(_) => warn!("successfully processed iptables changes"),
                            Err(e) => {
                                error!("failed processed iptables changes: {e}\n\nwill try again in 3 seconds");

                                thread::sleep(std::time::Duration::from_secs(3));

                                match self.process(proxy_port, targets) {
                                    Ok(_) => {
                                        warn!("successfully processed iptables changes after retry")
                                    }
                                    Err(e) => {
                                        error!("failed processed iptables changes after retry: {e}")
                                    }
                                }
                            }
                        }
                    }
                    Event::Any => continue,
                },
                Err(e) => panic!("got error from sender: {e}"),
            }
        });

        Ok(())
    }

    pub fn flush(&self) -> Result<(), anyhow::Error> {
        let mut rules_info = self
            .get_rules_info(CHAIN_PREROUTING)
            .map_err(|e| anyhow!("get_rules_info: {e}"))?;

        for rule_info in rules_info.iter() {
            self.iptables
                .delete_all("nat", CHAIN_PREROUTING, &rule_info.to_rule())
                .map_err(|e| anyhow!("delete: {e}"))?;
        }

        warn!("{CHAIN_PREROUTING} rules were deleted");

        rules_info = self
            .get_rules_info(CHAIN_BETA)
            .map_err(|e| anyhow!("get_rules_info: {e}"))?;

        for rule_info in rules_info.iter() {
            self.iptables
                .delete_all("nat", CHAIN_BETA, &rule_info.to_rule())
                .map_err(|e| anyhow!("delete: {e}"))?;
        }

        // other trash rules
        let other_rules = self
            .iptables
            .list("nat", CHAIN_BETA)
            .map_err(|e| anyhow!("list: {e}"))?;

        for rule in other_rules.iter() {
            self.iptables
                .delete_all("nat", CHAIN_BETA, &rule)
                .map_err(|e| anyhow!("delete: {e}"))?;
        }

        warn!("{CHAIN_BETA} rules were deleted");

        self.iptables
            .delete_chain("nat", CHAIN_BETA)
            .map_err(|e| anyhow!("delete_chain: {e}"))?;

        warn!("{CHAIN_BETA} chain was deleted");

        Ok(())
    }

    fn process(&self, proxy_port: u32, targets: &Vec<Target>) -> Result<(), anyhow::Error> {
        let prerouting_rules_info: Vec<RuleInfo> = targets
            .iter()
            .map(|t| RuleInfo::Prerouting { port_from: t.port })
            .collect();

        self.process_prerouting(&prerouting_rules_info)
            .map_err(|e| anyhow!("process_prerouting: {e}"))?;

        let beta_rules_info: Vec<RuleInfo> = targets
            .iter()
            .map(|t| RuleInfo::Beta {
                port_from: t.port,
                port_to: proxy_port,
            })
            .collect();

        self.process_beta(&beta_rules_info)
            .map_err(|e| anyhow!("process_beta: {e}"))?;

        Ok(())
    }

    fn process_prerouting(&self, rules_info: &Vec<RuleInfo>) -> Result<(), anyhow::Error> {
        let existing_rules_info = self
            .get_rules_info(CHAIN_PREROUTING)
            .map_err(|e| anyhow!("get_rules_info: {e}"))?;

        let rules_info_to_delete = self.get_rules_info_to_delete(&existing_rules_info, rules_info);

        if !rules_info_to_delete.is_empty() {
            self.delete_rules_from_prerouting(&rules_info_to_delete)
                .map_err(|e| anyhow!("delete_rules_from_prerouting: {e}"))?
        }

        let rules_info_to_add = self.get_rules_info_to_add(&existing_rules_info, rules_info);

        if !rules_info_to_add.is_empty() {
            self.add_rules_into_prerouting(&rules_info_to_add)
                .map_err(|e| anyhow!("add_rules_into_prerouting: {e}"))?
        }

        Ok(())
    }

    fn process_beta(&self, rules_info: &Vec<RuleInfo>) -> Result<(), anyhow::Error> {
        let existing_rules_info = self
            .get_rules_info(CHAIN_BETA)
            .map_err(|e| anyhow!("get_rules_info: {e}"))?;

        let rules_info_to_delete = self.get_rules_info_to_delete(&existing_rules_info, rules_info);

        if !rules_info_to_delete.is_empty() {
            self.delete_rules_from_beta(&rules_info_to_delete)
                .map_err(|e| anyhow!("delete_rules_from_beta: {e}"))?
        }

        let rules_info_to_add = self.get_rules_info_to_add(&existing_rules_info, rules_info);

        if !rules_info_to_add.is_empty() {
            self.add_rules_into_beta(&rules_info_to_add)
                .map_err(|e| anyhow!("add_rules_into_beta: {e}"))?
        }

        Ok(())
    }

    fn get_rules_info_to_add(
        &self,
        existing_rules_info: &Vec<RuleInfo>,
        new_rules_info: &Vec<RuleInfo>,
    ) -> Vec<RuleInfo> {
        let rules_info_to_add: Vec<RuleInfo> = new_rules_info
            .iter()
            .filter(|info| !existing_rules_info.contains(&info))
            .map(|info| *info)
            .collect();

        rules_info_to_add
    }

    fn get_rules_info_to_delete(
        &self,
        existing_rules_info: &Vec<RuleInfo>,
        new_rules_info: &Vec<RuleInfo>,
    ) -> Vec<RuleInfo> {
        let mut rules_info_to_delete: Vec<RuleInfo> = vec![];

        for existing_rule_info in existing_rules_info.iter() {
            let mut found = false;

            for rule_info in new_rules_info.iter() {
                if existing_rule_info.eq(&rule_info) {
                    found = true
                }
            }

            if !found {
                rules_info_to_delete.push(*existing_rule_info)
            }
        }

        rules_info_to_delete
    }

    fn get_rules_info(&self, chain: &str) -> Result<Vec<RuleInfo>, anyhow::Error> {
        let rules = self
            .iptables
            .list("nat", chain)
            .map_err(|e| anyhow!("list: {e}"))?;

        let mut rules_info: Vec<RuleInfo> = vec![];

        for rule in rules.iter() {
            let rule_info = match chain {
                CHAIN_BETA => match RuleInfo::from_beta_rule(rule) {
                    Some(res) => res,
                    None => {
                        continue;
                    }
                },
                CHAIN_PREROUTING => match RuleInfo::from_prerouting_rule(rule) {
                    Some(res) => res,
                    None => {
                        continue;
                    }
                },
                _ => {
                    continue;
                }
            };

            if !rule_info.is_empty() {
                rules_info.push(rule_info)
            }
        }

        Ok(rules_info)
    }

    fn add_beta_chain(&self) -> Result<(), anyhow::Error> {
        warn!("try to add {CHAIN_BETA} chain into iptables");

        if self
            .iptables
            .chain_exists("nat", CHAIN_BETA)
            .map_err(|e| anyhow!("chain_exists: {e}"))?
        {
            return Ok(());
        }

        return match self
            .iptables
            .execute("nat", format!("-N {CHAIN_BETA}").as_str())
        {
            Ok(res) => {
                if res.status.success() {
                    warn!("created {CHAIN_BETA} chain {:?}", res);
                    return Ok(());
                }

                Err(anyhow!("execute: {}", res.status.to_string()))
            }
            Err(e) => Err(anyhow!("execute: {e}")),
        };
    }

    fn add_rules_into_prerouting(&self, rules_info: &Vec<RuleInfo>) -> Result<(), anyhow::Error> {
        if !self
            .iptables
            .chain_exists("nat", CHAIN_BETA)
            .map_err(|e| anyhow!("chain_exists: {e}"))?
        {
            self.add_beta_chain()
                .map_err(|e| anyhow::anyhow!("add_beta_chain {e}"))?
        }

        for rule_info in rules_info.iter() {
            let rule = rule_info.to_rule();

            match self.iptables.append_unique("nat", CHAIN_PREROUTING, &rule) {
                Ok(_) => (),
                Err(e) => {
                    if e.to_string().ne("the rule exists in the table/chain") {
                        return Err(anyhow!("append_unique: {e}"));
                    };
                }
            }

            warn!("added rule into {CHAIN_PREROUTING}:\n {rule}")
        }

        Ok(())
    }

    fn add_rules_into_beta(&self, rules_info: &Vec<RuleInfo>) -> Result<(), anyhow::Error> {
        if !self.iptables.chain_exists("nat", CHAIN_BETA).unwrap() {
            self.add_beta_chain()
                .map_err(|e| anyhow::anyhow!("add_beta_chain {e}"))?
        }
        
        for rule_info in rules_info.iter() {
            let rule = rule_info.to_rule();

            match self.iptables.append_unique("nat", CHAIN_BETA, &rule) {
                Ok(_) => (),
                Err(e) => {
                    if e.to_string().ne("the rule exists in the table/chain") {
                        return Err(anyhow!("append_unique: {e}"));
                    };
                }
            }

            warn!("added rule into {CHAIN_BETA}:\n {rule}")
        }

        Ok(())
    }

    fn delete_rules_from_prerouting(
        &self,
        rules_info: &Vec<RuleInfo>,
    ) -> Result<(), anyhow::Error> {
        for info in rules_info.iter() {
            let rule = info.to_rule();

            self.iptables
                .delete_all("nat", CHAIN_PREROUTING, rule.as_str())
                .map_err(|e| anyhow!("delete_all: {e}"))?;

            warn!("deleted rule from {CHAIN_PREROUTING}:\n {rule}")
        }

        Ok(())
    }

    fn delete_rules_from_beta(&self, rules_info: &Vec<RuleInfo>) -> Result<(), anyhow::Error> {
        for info in rules_info.iter() {
            let rule = info.to_rule();

            self.iptables
                .delete_all("nat", CHAIN_BETA, rule.as_str())
                .map_err(|e| anyhow!("delete_all: {e}"))?;

            warn!("deleted rule from {CHAIN_BETA}:\n {rule}")
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum RuleInfo {
    Beta { port_from: u32, port_to: u32 },
    Prerouting { port_from: u32 },
}

impl PartialEq for RuleInfo {
    fn eq(&self, other: &Self) -> bool {
        match self {
            Self::Beta { port_from, port_to } => {
                let self_port_from = port_from;
                let self_port_to = port_to;

                match other {
                    Self::Beta { port_from, port_to } => {
                        self_port_from.eq(port_from) && self_port_to.eq(port_to)
                    }
                    _ => false,
                }
            }
            Self::Prerouting { port_from } => {
                let self_port_from = port_from;

                match other {
                    Self::Prerouting { port_from } => self_port_from.eq(port_from),
                    _ => false,
                }
            }
        }
    }

    fn ne(&self, other: &Self) -> bool {
        !self.eq(other) || !self.eq(other)
    }
}

impl RuleInfo {
    pub fn from_beta_rule(string_rule: &str) -> Option<RuleInfo> {
        let captures = match REGEX_RULE_BETA.clone().captures(string_rule) {
            Some(res) => res,
            None => return None,
        };

        return Some(RuleInfo::Beta {
            port_from: captures
                .name("port_from")
                .unwrap()
                .as_str()
                .to_string()
                .parse::<u32>()
                .unwrap(),
            port_to: captures
                .name("port_to")
                .unwrap()
                .as_str()
                .to_string()
                .parse::<u32>()
                .unwrap(),
        });
    }

    pub fn from_prerouting_rule(string_rule: &str) -> Option<RuleInfo> {
        let captures = match REGEX_RULE_PREROUTING.clone().captures(string_rule) {
            Some(res) => res,
            None => return None,
        };

        return Some(RuleInfo::Prerouting {
            port_from: captures
                .name("port_from")
                .unwrap()
                .as_str()
                .to_string()
                .parse::<u32>()
                .unwrap(),
        });
    }

    pub fn to_rule(&self) -> String {
        match self {
            Self::Beta { port_from, port_to } => format!(
                "-p tcp --dport {} -j REDIRECT --to-ports {}",
                port_from, port_to
            ),
            Self::Prerouting { port_from } => {
                format!("-p tcp --dport {} -j {CHAIN_BETA}", port_from)
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Self::Beta { port_from, port_to } => port_from.eq(&0) && port_to.eq(&0),
            Self::Prerouting { port_from } => port_from.eq(&0),
        }
    }
}
