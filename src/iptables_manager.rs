use std::{fmt::Display, thread, vec};

use anyhow::anyhow;
use iptables::IPTables;
use lazy_static::lazy_static;
use regex::Regex;

use crate::config::{Event, ProxySettingsConfig};

const CHAIN_LASTOCHKA: &str = "LASTOCHKA";
const CHAIN_PREROUTING: &str = "PREROUTING";

lazy_static! {
    pub static ref REGEX_RULE_LASTOCHKA: Regex = Regex::new(
        r"-A LASTOCHKA -p tcp -m tcp --dport (?P<port_from>\d{1,5}) -j REDIRECT --to-ports (?P<port_to>\d{1,5})").unwrap();
    pub static ref REGEX_RULE_PREROUTING: Regex = Regex::new(
        r"-A PREROUTING -p tcp -m tcp --dport (?P<port_from>\d{1,5}) -j LASTOCHKA").unwrap();
}

pub struct Manager {
    iptables: IPTables,
    proxy_settings_config: ProxySettingsConfig,
    proxy_port: u32,
}

impl Manager {
    pub fn new(proxy_port: u32, config: ProxySettingsConfig) -> Result<Self, anyhow::Error> {
        let res = iptables::new(false).map_err(|e| anyhow!("{e}"))?;

        let manager: Manager = Manager {
            iptables: res,
            proxy_settings_config: config,
            proxy_port,
        };

        manager
            .add_lastocka_chain()
            .map_err(|e| anyhow!("add_lastocka_chain: {e}"))?;

        Ok(manager)
    }

    pub fn watch_for_proxy_settings(self) {
        std::thread::spawn(move || loop {
            match self.proxy_settings_config.recv() {
                Ok(event) => match event {
                    Event::TargetsModify => {
                        let targets = self.proxy_settings_config.targets();
                        let mut rules_info: Vec<RuleInfo> = vec![];

                        for target in targets {
                            rules_info.push(RuleInfo {
                                port_from: target.port,
                                port_to: self.proxy_port,
                            })
                        }

                        match self.process(&rules_info) {
                            Ok(_) => warn!("successfully processed iptables changes"),
                            Err(e) => {
                                error!("failed processed iptables changes: {e}\n\nwill try again in 3 seconds");

                                thread::sleep(std::time::Duration::from_secs(3));

                                match self.process(&rules_info) {
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
    }

    fn process(&self, rules_info: &Vec<RuleInfo>) -> Result<(), anyhow::Error> {
        self.process_prerouting(rules_info)
            .map_err(|e| anyhow!("process_prerouting: {e}"))?;
        self.process_lastochka(rules_info)
            .map_err(|e| anyhow!("process_lastochka: {e}"))?;

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

    fn process_lastochka(&self, rules_info: &Vec<RuleInfo>) -> Result<(), anyhow::Error> {
        let existing_rules_info = self
            .get_rules_info(CHAIN_LASTOCHKA)
            .map_err(|e| anyhow!("get_rules_info: {e}"))?;

        let rules_info_to_delete = self.get_rules_info_to_delete(&existing_rules_info, rules_info);

        if !rules_info_to_delete.is_empty() {
            self.delete_rules_from_lastochka(&rules_info_to_delete)
                .map_err(|e| anyhow!("delete_rules_from_lastochka: {e}"))?
        }

        let rules_info_to_add = self.get_rules_info_to_add(&existing_rules_info, rules_info);

        if !rules_info_to_add.is_empty() {
            self.add_rules_into_lastochka(&rules_info_to_add)
                .map_err(|e| anyhow!("add_rules_into_lastochka: {e}"))?
        }

        Ok(())
    }

    fn get_rules_info_to_add(
        &self,
        existing_rules_info: &Vec<RuleInfo>,
        new_rules_info: &Vec<RuleInfo>,
    ) -> Vec<RuleInfo> {
        let mut rules_info_to_add: Vec<RuleInfo> = vec![];

        for rule_info in new_rules_info.iter() {
            if !existing_rules_info.contains(&rule_info) {
                rules_info_to_add.push(*rule_info)
            }
        }

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
                CHAIN_LASTOCHKA => match RuleInfo::from_lastochka_rule(rule) {
                    Some(res) => res,
                    None => {
                        continue;
                    }
                },
                CHAIN_PREROUTING => match RuleInfo::from_prerouting_rule(self.proxy_port, rule) {
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

    fn add_lastocka_chain(&self) -> Result<(), anyhow::Error> {
        if self
            .iptables
            .chain_exists("nat", CHAIN_LASTOCHKA)
            .map_err(|e| anyhow!("chain_exists: {e}"))?
        {
            return Ok(());
        }

        Ok(
            match self
                .iptables
                .execute("nat", format!("-N {CHAIN_LASTOCHKA}").as_str())
            {
                Ok(res) => warn!("created {CHAIN_LASTOCHKA} chain {:?}", res),
                Err(e) => return Err(anyhow::anyhow!("execute: {e}")),
            },
        )
    }

    fn add_rules_into_prerouting(&self, rules_info: &Vec<RuleInfo>) -> Result<(), anyhow::Error> {
        if !self
            .iptables
            .chain_exists("nat", CHAIN_LASTOCHKA)
            .map_err(|e| anyhow!("chain_exists: {e}"))?
        {
            self.add_lastocka_chain()
                .map_err(|e| anyhow::anyhow!("add_lastocka_chain {e}"))?
        }

        for rule_info in rules_info.iter() {
            let rule = rule_info.to_prerouting_rule();

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

    fn add_rules_into_lastochka(&self, rules_info: &Vec<RuleInfo>) -> Result<(), anyhow::Error> {
        if !self.iptables.chain_exists("nat", CHAIN_LASTOCHKA).unwrap() {
            self.add_lastocka_chain()
                .map_err(|e| anyhow::anyhow!("add_lastocka_chain {e}"))?
        }

        for rule_info in rules_info.iter() {
            let rule = rule_info.to_lastochka_rule();

            match self.iptables.append_unique("nat", CHAIN_LASTOCHKA, &rule) {
                Ok(_) => (),
                Err(e) => {
                    if e.to_string().ne("the rule exists in the table/chain") {
                        return Err(anyhow!("append_unique: {e}"));
                    };
                }
            }

            warn!("added rule into {CHAIN_LASTOCHKA}:\n {rule}")
        }

        Ok(())
    }

    fn delete_rules_from_prerouting(
        &self,
        rules_info: &Vec<RuleInfo>,
    ) -> Result<(), anyhow::Error> {
        for info in rules_info.iter() {
            let rule = info.to_prerouting_rule();

            self.iptables
                .delete_all("nat", CHAIN_PREROUTING, rule.as_str())
                .map_err(|e| anyhow!("delete_all: {e}"))?;

            warn!("deleted rule from {CHAIN_PREROUTING}:\n {rule}")
        }

        Ok(())
    }

    fn delete_rules_from_lastochka(&self, rules_info: &Vec<RuleInfo>) -> Result<(), anyhow::Error> {
        for info in rules_info.iter() {
            let rule = info.to_lastochka_rule();

            self.iptables
                .delete_all("nat", CHAIN_LASTOCHKA, rule.as_str())
                .map_err(|e| anyhow!("delete_all: {e}"))?;

            warn!("deleted rule from {CHAIN_LASTOCHKA}:\n {rule}")
        }

        Ok(())
    }

    pub fn delete_all_rules(self) -> Result<(), anyhow::Error> {
        Ok(())
    }

    pub fn flush_all(self) -> Result<(), anyhow::Error> {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RuleInfo {
    pub port_from: u32,
    pub port_to: u32,
}

impl Display for RuleInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "`port_from: {}`, `port_to: {})`",
            self.port_from, self.port_to
        )
    }
}

impl PartialEq for RuleInfo {
    fn eq(&self, other: &Self) -> bool {
        self.port_from.eq(&other.port_from) && self.port_to.eq(&other.port_to)
    }

    fn ne(&self, other: &Self) -> bool {
        self.port_from.ne(&other.port_from) || self.port_to.ne(&other.port_to)
    }
}

impl RuleInfo {
    pub fn fill_port_to(port: u32) -> Self {
        RuleInfo {
            port_from: 0,
            port_to: port,
        }
    }

    pub fn from_lastochka_rule(string_rule: &str) -> Option<RuleInfo> {
        let captures = match REGEX_RULE_LASTOCHKA.clone().captures(string_rule) {
            Some(res) => res,
            None => return None,
        };

        return Some(RuleInfo {
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

    pub fn from_prerouting_rule(port_to: u32, string_rule: &str) -> Option<RuleInfo> {
        let captures = match REGEX_RULE_PREROUTING.clone().captures(string_rule) {
            Some(res) => res,
            None => return None,
        };

        return Some(RuleInfo {
            port_from: captures
                .name("port_from")
                .unwrap()
                .as_str()
                .to_string()
                .parse::<u32>()
                .unwrap(),
            port_to,
        });
    }

    pub fn to_lastochka_rule(&self) -> String {
        format!(
            "-p tcp --dport {} -j REDIRECT --to-ports {}",
            self.port_from, self.port_to
        )
    }

    pub fn to_prerouting_rule(&self) -> String {
        format!("-p tcp --dport {} -j {CHAIN_LASTOCHKA}", self.port_from)
    }

    pub fn is_empty(&self) -> bool {
        self.port_from.eq(&0) && self.port_to.eq(&0)
    }
}
