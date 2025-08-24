use anyhow::{Context, Result};
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::fs;

// Table definitions for YARA rules database
const YARA_RULES_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("yara_rules");
const RULE_METADATA_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("rule_metadata");
const THREAT_INTEL_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("threat_intel");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRule {
    pub id: String,
    pub name: String,
    pub content: String,
    pub author: String,
    pub description: String,
    pub tags: Vec<String>,
    pub severity: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub version: String,
    pub hash: String,
    pub source: String,
    pub mitre_tactics: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub threat_actors: Vec<String>,
    pub malware_families: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMetadata {
    pub rule_id: String,
    pub performance_score: f64,
    pub false_positive_rate: f64,
    pub detection_count: u64,
    pub last_detection: Option<chrono::DateTime<chrono::Utc>>,
    pub effectiveness_rating: String,
    pub ai_confidence_score: f64,
    pub quantum_threat_relevance: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelIndicator {
    pub id: String,
    pub indicator_type: String,
    pub value: String,
    pub confidence: f64,
    pub threat_score: f64,
    pub first_seen: chrono::DateTime<chrono::Utc>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    pub source_feeds: Vec<String>,
    pub associated_campaigns: Vec<String>,
    pub mitre_mapping: Vec<String>,
    pub quantum_resistant: bool,
}

pub struct YaraRulesRedbHook {
    db: Database,
    db_path: String,
}

impl YaraRulesRedbHook {
    pub async fn new<P: AsRef<Path>>(db_path: P) -> Result<Self> {
        let db_path_str = db_path.as_ref().to_string_lossy().to_string();
        
        // Ensure directory exists
        if let Some(parent) = db_path.as_ref().parent() {
            fs::create_dir_all(parent).await
                .context("Failed to create database directory")?;
        }

        let db = Database::create(&db_path_str)
            .context("Failed to create YARA rules database")?;

        // Initialize tables
        let write_txn = db.begin_write()
            .context("Failed to begin write transaction")?;
        
        {
            let _rules_table = write_txn.open_table(YARA_RULES_TABLE)
                .context("Failed to open YARA rules table")?;
            let _metadata_table = write_txn.open_table(RULE_METADATA_TABLE)
                .context("Failed to open rule metadata table")?;
            let _intel_table = write_txn.open_table(THREAT_INTEL_TABLE)
                .context("Failed to open threat intel table")?;
        }
        
        write_txn.commit()
            .context("Failed to commit table initialization")?;

        log::info!("Initialized YARA rules ReDB database at: {}", db_path_str);

        Ok(Self {
            db,
            db_path: db_path_str,
        })
    }

    pub async fn store_yara_rule(&self, rule: &YaraRule) -> Result<()> {
        let rule_data = bincode::serialize(rule)
            .context("Failed to serialize YARA rule")?;

        let write_txn = self.db.begin_write()
            .context("Failed to begin write transaction")?;
        
        {
            let mut table = write_txn.open_table(YARA_RULES_TABLE)
                .context("Failed to open YARA rules table")?;
            
            table.insert(&rule.id, rule_data.as_slice())
                .context("Failed to insert YARA rule")?;
        }
        
        write_txn.commit()
            .context("Failed to commit YARA rule storage")?;

        log::info!("Stored YARA rule: {} ({})", rule.name, rule.id);
        Ok(())
    }

    pub async fn get_yara_rule(&self, rule_id: &str) -> Result<Option<YaraRule>> {
        let read_txn = self.db.begin_read()
            .context("Failed to begin read transaction")?;
        
        let table = read_txn.open_table(YARA_RULES_TABLE)
            .context("Failed to open YARA rules table")?;
        
        if let Some(rule_data) = table.get(rule_id)
            .context("Failed to get YARA rule")? {
            
            let rule: YaraRule = bincode::deserialize(rule_data.value())
                .context("Failed to deserialize YARA rule")?;
            
            Ok(Some(rule))
        } else {
            Ok(None)
        }
    }

    pub async fn list_yara_rules(&self) -> Result<Vec<YaraRule>> {
        let read_txn = self.db.begin_read()
            .context("Failed to begin read transaction")?;
        
        let table = read_txn.open_table(YARA_RULES_TABLE)
            .context("Failed to open YARA rules table")?;
        
        let mut rules = Vec::new();
        
        for result in table.iter()? {
            let (_key, value) = result?;
            let rule: YaraRule = bincode::deserialize(value.value())
                .context("Failed to deserialize YARA rule")?;
            rules.push(rule);
        }
        
        Ok(rules)
    }

    pub async fn update_rule_metadata(&self, metadata: &RuleMetadata) -> Result<()> {
        let metadata_data = bincode::serialize(metadata)
            .context("Failed to serialize rule metadata")?;

        let write_txn = self.db.begin_write()
            .context("Failed to begin write transaction")?;
        
        {
            let mut table = write_txn.open_table(RULE_METADATA_TABLE)
                .context("Failed to open rule metadata table")?;
            
            table.insert(&metadata.rule_id, metadata_data.as_slice())
                .context("Failed to insert rule metadata")?;
        }
        
        write_txn.commit()
            .context("Failed to commit rule metadata update")?;

        log::debug!("Updated metadata for rule: {}", metadata.rule_id);
        Ok(())
    }

    pub async fn get_rule_metadata(&self, rule_id: &str) -> Result<Option<RuleMetadata>> {
        let read_txn = self.db.begin_read()
            .context("Failed to begin read transaction")?;
        
        let table = read_txn.open_table(RULE_METADATA_TABLE)
            .context("Failed to open rule metadata table")?;
        
        if let Some(metadata_data) = table.get(rule_id)
            .context("Failed to get rule metadata")? {
            
            let metadata: RuleMetadata = bincode::deserialize(metadata_data.value())
                .context("Failed to deserialize rule metadata")?;
            
            Ok(Some(metadata))
        } else {
            Ok(None)
        }
    }

    pub async fn store_threat_intel(&self, indicator: &ThreatIntelIndicator) -> Result<()> {
        let intel_data = bincode::serialize(indicator)
            .context("Failed to serialize threat intel indicator")?;

        let write_txn = self.db.begin_write()
            .context("Failed to begin write transaction")?;
        
        {
            let mut table = write_txn.open_table(THREAT_INTEL_TABLE)
                .context("Failed to open threat intel table")?;
            
            table.insert(&indicator.id, intel_data.as_slice())
                .context("Failed to insert threat intel indicator")?;
        }
        
        write_txn.commit()
            .context("Failed to commit threat intel storage")?;

        log::info!("Stored threat intel indicator: {} (confidence: {:.2})", 
                  indicator.value, indicator.confidence);
        Ok(())
    }

    pub async fn get_threat_intel_by_value(&self, value: &str) -> Result<Vec<ThreatIntelIndicator>> {
        let read_txn = self.db.begin_read()
            .context("Failed to begin read transaction")?;
        
        let table = read_txn.open_table(THREAT_INTEL_TABLE)
            .context("Failed to open threat intel table")?;
        
        let mut indicators = Vec::new();
        
        for result in table.iter()? {
            let (_key, intel_data) = result?;
            let indicator: ThreatIntelIndicator = bincode::deserialize(intel_data.value())
                .context("Failed to deserialize threat intel indicator")?;
            
            if indicator.value.contains(value) {
                indicators.push(indicator);
            }
        }
        
        Ok(indicators)
    }

    pub async fn get_high_confidence_indicators(&self, min_confidence: f64) -> Result<Vec<ThreatIntelIndicator>> {
        let read_txn = self.db.begin_read()
            .context("Failed to begin read transaction")?;
        
        let table = read_txn.open_table(THREAT_INTEL_TABLE)
            .context("Failed to open threat intel table")?;
        
        let mut indicators = Vec::new();
        
        for result in table.iter()? {
            let (_key, intel_data) = result?;
            let indicator: ThreatIntelIndicator = bincode::deserialize(intel_data.value())
                .context("Failed to deserialize threat intel indicator")?;
            
            if indicator.confidence >= min_confidence {
                indicators.push(indicator);
            }
        }
        
        // Sort by confidence descending
        indicators.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
        
        Ok(indicators)
    }

    pub async fn cleanup_old_indicators(&self, days_old: i64) -> Result<u64> {
        let cutoff_date = chrono::Utc::now() - chrono::Duration::days(days_old);
        let mut removed_count = 0u64;

        let write_txn = self.db.begin_write()
            .context("Failed to begin write transaction")?;
        
        {
            let mut table = write_txn.open_table(THREAT_INTEL_TABLE)
                .context("Failed to open threat intel table")?;
            
            let mut keys_to_remove = Vec::new();
            
            for result in table.iter()? {
                let (key, intel_data) = result?;
                let indicator: ThreatIntelIndicator = bincode::deserialize(intel_data.value())
                    .context("Failed to deserialize threat intel indicator")?;
                
                if indicator.last_seen < cutoff_date {
                    keys_to_remove.push(key.value().to_string());
                }
            }
            
            for key in keys_to_remove {
                table.remove(&key)?;
                removed_count += 1;
            }
        }
        
        write_txn.commit()
            .context("Failed to commit cleanup transaction")?;

        log::info!("Cleaned up {} old threat intel indicators", removed_count);
        Ok(removed_count)
    }

    pub async fn get_database_stats(&self) -> Result<DatabaseStats> {
        let read_txn = self.db.begin_read()
            .context("Failed to begin read transaction")?;
        
        let rules_table = read_txn.open_table(YARA_RULES_TABLE)
            .context("Failed to open YARA rules table")?;
        let metadata_table = read_txn.open_table(RULE_METADATA_TABLE)
            .context("Failed to open rule metadata table")?;
        let intel_table = read_txn.open_table(THREAT_INTEL_TABLE)
            .context("Failed to open threat intel table")?;
        
        let rules_count = rules_table.len()? as u64;
        let metadata_count = metadata_table.len()? as u64;
        let intel_count = intel_table.len()? as u64;
        
        Ok(DatabaseStats {
            yara_rules_count: rules_count,
            metadata_entries_count: metadata_count,
            threat_intel_count: intel_count,
            database_path: self.db_path.clone(),
            last_updated: chrono::Utc::now(),
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DatabaseStats {
    pub yara_rules_count: u64,
    pub metadata_entries_count: u64,
    pub threat_intel_count: u64,
    pub database_path: String,
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

// Hook integration functions
pub async fn initialize_yara_rules_hook(db_path: &str) -> Result<YaraRulesRedbHook> {
    YaraRulesRedbHook::new(db_path).await
}

pub async fn sync_yara_rules_from_directory(
    hook: &YaraRulesRedbHook,
    rules_directory: &str,
) -> Result<u64> {
    let mut synced_count = 0u64;
    let mut entries = fs::read_dir(rules_directory).await
        .context("Failed to read rules directory")?;

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        
        if path.extension().and_then(|s| s.to_str()) == Some("yar") ||
           path.extension().and_then(|s| s.to_str()) == Some("yara") {
            
            let content = fs::read_to_string(&path).await
                .context("Failed to read YARA rule file")?;
            
            let rule = YaraRule {
                id: uuid::Uuid::new_v4().to_string(),
                name: path.file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown")
                    .to_string(),
                content,
                author: "Auto-imported".to_string(),
                description: format!("Imported from {}", path.display()),
                tags: vec!["auto-imported".to_string()],
                severity: "medium".to_string(),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                version: "1.0".to_string(),
                hash: format!("{:x}", md5::compute(&content)),
                source: path.to_string_lossy().to_string(),
                mitre_tactics: vec![],
                mitre_techniques: vec![],
                threat_actors: vec![],
                malware_families: vec![],
            };
            
            hook.store_yara_rule(&rule).await?;
            synced_count += 1;
        }
    }
    
    log::info!("Synced {} YARA rules from directory: {}", synced_count, rules_directory);
    Ok(synced_count)
}