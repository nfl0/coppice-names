//! SQLite host storage for transactional Coppice Names replay.
//!
//! Protocol authority remains authenticated Zcash history plus the Names
//! reducer. This crate persists the reducer's exact record deltas. SQLite
//! indexes are rebuildable acceleration and are never accepted as protocol
//! evidence on their own.

#![forbid(unsafe_code)]

use coppice::transaction::TransactionHost;
use coppice_names::{
    protocol::{CanonicalUa, CommitRef, Commitment, FieldElement, Name, NameId, Network, StateRef},
    reducer::{Head, ReducerTip, StateDelta},
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_MINIMUM_ROLLBACK_BLOCKS: u32 = 100;

const CREATE_DERIVED_INDEXES: &str = "
CREATE INDEX IF NOT EXISTS names_heads_future_nf
    ON names_heads(future_nf);
CREATE INDEX IF NOT EXISTS names_heads_active_expiry
    ON names_heads(expiry_height, name_id)
    WHERE terminal_height IS NULL;
CREATE INDEX IF NOT EXISTS names_heads_terminal_height
    ON names_heads(terminal_height, name_id)
    WHERE terminal_height IS NOT NULL;
CREATE INDEX IF NOT EXISTS names_pending_commits_height
    ON names_pending_commits(height, tx_index, txid);
";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coverage {
    /// Complete local chain-derived Names state for one deployment.
    Complete,
    /// Evidence sufficient only for one exact NameId.
    Exact(NameId),
    /// Account-selected owned names; never sufficient for arbitrary Missing.
    Owned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreIdentity {
    pub deployment_id: [u8; 32],
    pub ruleset_fingerprint: [u8; 32],
    pub network: Network,
    pub coverage: Coverage,
    pub minimum_rollback_blocks: u32,
}

impl StoreIdentity {
    pub fn new(
        deployment_id: [u8; 32],
        ruleset_fingerprint: [u8; 32],
        network: Network,
        coverage: Coverage,
    ) -> Self {
        Self {
            deployment_id,
            ruleset_fingerprint,
            network,
            coverage,
            minimum_rollback_blocks: DEFAULT_MINIMUM_ROLLBACK_BLOCKS,
        }
    }
}

#[derive(Debug)]
pub enum StoreError {
    Sqlite(rusqlite::Error),
    Encoding(serde_json::Error),
    UnsupportedSchema { actual: u32 },
    IdentityMismatch,
    CoverageMismatch,
    CoverageViolation,
    TipMismatch,
    NonSequentialDelta,
    AuthoritativeRecordMismatch,
    MissingRollbackJournal,
    WrongTipHash,
    FinalizationBeyondTip,
    InsufficientRollbackRetention,
    IntegrityCheckFailed(String),
    InvalidStoredRecord,
    InjectedFailure,
}

impl From<rusqlite::Error> for StoreError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

impl From<serde_json::Error> for StoreError {
    fn from(value: serde_json::Error) -> Self {
        Self::Encoding(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadRecord {
    pub name: String,
    pub ua: String,
    pub producer: StateRef,
    pub commitment: [u8; 32],
    pub future_nf: [u8; 32],
    pub producer_epoch: u32,
    pub expiry_height: u32,
    pub terminal_height: Option<u32>,
}

impl From<&Head> for HeadRecord {
    fn from(value: &Head) -> Self {
        Self {
            name: value.name.as_str().to_owned(),
            ua: value.ua.as_str().to_owned(),
            producer: value.producer,
            commitment: value.commitment.to_bytes(),
            future_nf: value.future_nf.to_bytes(),
            producer_epoch: value.producer_epoch,
            expiry_height: value.expiry_height,
            terminal_height: value.terminal_height,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MissingAuthority {
    Authoritative,
    InsufficientCoverage,
    StaleTip,
}

pub struct SqliteNamesStore {
    connection: Connection,
    identity: StoreIdentity,
}

pub struct SqliteNamesTransaction<'conn> {
    transaction: rusqlite::Transaction<'conn>,
    identity: StoreIdentity,
}

impl SqliteNamesStore {
    pub fn open(path: impl AsRef<Path>, identity: StoreIdentity) -> Result<Self, StoreError> {
        Self::from_connection(Connection::open(path)?, identity)
    }

    pub fn open_in_memory(identity: StoreIdentity) -> Result<Self, StoreError> {
        Self::from_connection(Connection::open_in_memory()?, identity)
    }

    fn from_connection(
        connection: Connection,
        identity: StoreIdentity,
    ) -> Result<Self, StoreError> {
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             CREATE TABLE IF NOT EXISTS names_metadata (
                 singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                 schema_version INTEGER NOT NULL,
                 deployment_id BLOB NOT NULL,
                 ruleset_fingerprint BLOB NOT NULL,
                 network INTEGER NOT NULL,
                 coverage_kind INTEGER NOT NULL,
                 coverage_name_id BLOB,
                 minimum_rollback_blocks INTEGER NOT NULL,
                 tip_height INTEGER,
                 tip_hash BLOB,
                 finalized_height INTEGER,
                 core_snapshot BLOB
             );
             CREATE TABLE IF NOT EXISTS names_heads (
                 name_id BLOB PRIMARY KEY,
                 name TEXT NOT NULL,
                 ua TEXT NOT NULL,
                 producer_height INTEGER NOT NULL,
                 producer_tx_index INTEGER NOT NULL,
                 producer_txid BLOB NOT NULL,
                 producer_action_index INTEGER NOT NULL,
                 commitment BLOB NOT NULL,
                 future_nf BLOB NOT NULL,
                 producer_epoch INTEGER NOT NULL,
                 expiry_height INTEGER NOT NULL,
                 terminal_height INTEGER
             );
             CREATE TABLE IF NOT EXISTS names_pending_commits (
                 height INTEGER NOT NULL,
                 tx_index INTEGER NOT NULL,
                 txid BLOB NOT NULL,
                 commitment BLOB NOT NULL,
                 PRIMARY KEY(height, tx_index, txid)
             );
             CREATE TABLE IF NOT EXISTS names_rollback_blocks (
                 height INTEGER PRIMARY KEY,
                 hash BLOB NOT NULL,
                 previous_tip_height INTEGER,
                 previous_tip_hash BLOB
             );
             CREATE TABLE IF NOT EXISTS names_rollback_heads (
                 block_height INTEGER NOT NULL REFERENCES names_rollback_blocks(height) ON DELETE CASCADE,
                 name_id BLOB NOT NULL,
                 previous_record BLOB,
                 PRIMARY KEY(block_height, name_id)
             );
             CREATE TABLE IF NOT EXISTS names_rollback_commits (
                 block_height INTEGER NOT NULL REFERENCES names_rollback_blocks(height) ON DELETE CASCADE,
                 height INTEGER NOT NULL,
                 tx_index INTEGER NOT NULL,
                 txid BLOB NOT NULL,
                 previous_commitment BLOB,
                 PRIMARY KEY(block_height, height, tx_index, txid)
             );",
        )?;
        connection.execute_batch(CREATE_DERIVED_INDEXES)?;
        initialize_or_validate_metadata(&connection, identity)?;
        Ok(Self {
            connection,
            identity,
        })
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    pub fn tip(&self) -> Result<Option<ReducerTip>, StoreError> {
        read_tip(&self.connection)
    }

    pub fn head(&self, name_id: NameId) -> Result<Option<HeadRecord>, StoreError> {
        read_head(&self.connection, name_id)
    }

    /// Whether this store's authenticated coverage can establish `Missing` at
    /// the caller's exact tip. Negative results are never timeless cache data.
    pub fn missing_authority(
        &self,
        name_id: NameId,
        requested_tip: ReducerTip,
    ) -> Result<MissingAuthority, StoreError> {
        if self.tip()? != Some(requested_tip) {
            return Ok(MissingAuthority::StaleTip);
        }
        Ok(match self.identity.coverage {
            Coverage::Complete => MissingAuthority::Authoritative,
            Coverage::Exact(expected) if expected == name_id => MissingAuthority::Authoritative,
            Coverage::Exact(_) | Coverage::Owned => MissingAuthority::InsufficientCoverage,
        })
    }

    pub fn verify_integrity(&self) -> Result<(), StoreError> {
        let quick_check: String = self
            .connection
            .query_row("PRAGMA quick_check", [], |row| row.get(0))?;
        if quick_check != "ok" {
            return Err(StoreError::IntegrityCheckFailed(quick_check));
        }
        let foreign_key_failure = self
            .connection
            .query_row("PRAGMA foreign_key_check", [], |_| Ok(()))
            .optional()?;
        if foreign_key_failure.is_some() {
            return Err(StoreError::IntegrityCheckFailed(
                "foreign key check failed".to_owned(),
            ));
        }
        Ok(())
    }

    /// Recreates every non-authoritative native index from authoritative rows.
    pub fn rebuild_derived_indexes(&mut self) -> Result<(), StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(
            "DROP INDEX IF EXISTS names_heads_future_nf;
             DROP INDEX IF EXISTS names_heads_active_expiry;
             DROP INDEX IF EXISTS names_heads_terminal_height;
             DROP INDEX IF EXISTS names_pending_commits_height;",
        )?;
        transaction.execute_batch(CREATE_DERIVED_INDEXES)?;
        transaction.commit()?;
        self.verify_integrity()
    }

    pub fn derived_indexes_present(&self) -> Result<bool, StoreError> {
        let count: u32 = self.connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type = 'index' AND name IN (
                 'names_heads_future_nf',
                 'names_heads_active_expiry',
                 'names_heads_terminal_height',
                 'names_pending_commits_height'
             )",
            [],
            |row| row.get(0),
        )?;
        Ok(count == 4)
    }
}

impl TransactionHost for SqliteNamesStore {
    type Error = StoreError;
    type Transaction<'tx> = SqliteNamesTransaction<'tx>;

    fn with_transaction<R, F>(&mut self, operation: F) -> Result<R, Self::Error>
    where
        F: for<'tx> FnOnce(&mut Self::Transaction<'tx>) -> Result<R, Self::Error>,
    {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut transaction = SqliteNamesTransaction {
            transaction,
            identity: self.identity,
        };
        let output = operation(&mut transaction)?;
        transaction.transaction.commit()?;
        Ok(output)
    }
}

impl SqliteNamesTransaction<'_> {
    /// Gives the host access to the same borrowed SQLite transaction for
    /// wallet-owned tables and other atomic layers.
    pub fn connection(&self) -> &Connection {
        &self.transaction
    }

    /// Runs one block inside the outer batch transaction. Returning an error
    /// rolls back only this block's writes, allowing the host to commit the
    /// preceding deterministic prefix and stop. A panic still unwinds the
    /// outer transaction and therefore publishes no part of the batch.
    pub fn with_block_savepoint<R, F>(&mut self, operation: F) -> Result<R, StoreError>
    where
        F: FnOnce(&mut Self) -> Result<R, StoreError>,
    {
        self.transaction
            .execute_batch("SAVEPOINT coppice_names_block")?;
        match operation(self) {
            Ok(output) => {
                self.transaction
                    .execute_batch("RELEASE SAVEPOINT coppice_names_block")?;
                Ok(output)
            }
            Err(error) => {
                self.transaction.execute_batch(
                    "ROLLBACK TO SAVEPOINT coppice_names_block;
                     RELEASE SAVEPOINT coppice_names_block;",
                )?;
                Err(error)
            }
        }
    }

    pub fn put_core_snapshot(&mut self, snapshot: &[u8]) -> Result<(), StoreError> {
        self.transaction.execute(
            "UPDATE names_metadata SET core_snapshot = ?1 WHERE singleton = 1",
            [snapshot],
        )?;
        Ok(())
    }

    pub fn apply_delta(&mut self, delta: &StateDelta) -> Result<(), StoreError> {
        if read_tip(&self.transaction)? != delta.from_tip {
            return Err(StoreError::TipMismatch);
        }
        let to_tip = delta.to_tip.ok_or(StoreError::NonSequentialDelta)?;
        if delta.from_tip.is_some_and(|from| {
            from.height.checked_add(1) != Some(to_tip.height) || from.hash == to_tip.hash
        }) {
            return Err(StoreError::NonSequentialDelta);
        }
        if let Coverage::Exact(expected) = self.identity.coverage
            && delta.heads.iter().any(|change| change.name_id != expected)
        {
            return Err(StoreError::CoverageViolation);
        }
        self.transaction.execute(
            "INSERT INTO names_rollback_blocks(
                 height, hash, previous_tip_height, previous_tip_hash
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                to_tip.height,
                to_tip.hash.as_slice(),
                delta.from_tip.map(|tip| tip.height),
                delta.from_tip.map(|tip| tip.hash.to_vec()),
            ],
        )?;

        for change in &delta.heads {
            if let Some(head) = &change.previous {
                validate_head(
                    change.name_id,
                    &HeadRecord::from(head),
                    self.identity.network,
                    delta.from_tip.map(|tip| tip.height),
                )?;
            }
            if let Some(head) = &change.current {
                validate_head(
                    change.name_id,
                    &HeadRecord::from(head),
                    self.identity.network,
                    Some(to_tip.height),
                )?;
            }
            let actual = read_head(&self.transaction, change.name_id)?;
            if actual != change.previous.as_ref().map(HeadRecord::from) {
                return Err(StoreError::AuthoritativeRecordMismatch);
            }
            let previous = change
                .previous
                .as_ref()
                .map(HeadRecord::from)
                .map(|record| serde_json::to_vec(&record))
                .transpose()?;
            self.transaction.execute(
                "INSERT INTO names_rollback_heads(block_height, name_id, previous_record)
                 VALUES (?1, ?2, ?3)",
                params![
                    to_tip.height,
                    change.name_id.to_bytes().as_slice(),
                    previous
                ],
            )?;
            write_head(
                &self.transaction,
                change.name_id,
                change.current.as_ref().map(HeadRecord::from).as_ref(),
            )?;
        }

        for change in &delta.commits {
            let actual = read_commit(&self.transaction, change.reference)?;
            if actual != change.previous.map(Commitment::to_bytes) {
                return Err(StoreError::AuthoritativeRecordMismatch);
            }
            self.transaction.execute(
                "INSERT INTO names_rollback_commits(
                     block_height, height, tx_index, txid, previous_commitment
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    to_tip.height,
                    change.reference.height,
                    change.reference.tx_index,
                    change.reference.txid.as_slice(),
                    change.previous.map(|value| value.to_bytes().to_vec()),
                ],
            )?;
            write_commit(
                &self.transaction,
                change.reference,
                change.current.map(Commitment::to_bytes),
            )?;
        }

        write_tip(&self.transaction, Some(to_tip))
    }

    /// Restores one tip from the bounded authoritative rollback journal.
    pub fn rollback_tip(
        &mut self,
        expected_hash: [u8; 32],
    ) -> Result<Option<ReducerTip>, StoreError> {
        let tip = read_tip(&self.transaction)?.ok_or(StoreError::MissingRollbackJournal)?;
        if tip.hash != expected_hash {
            return Err(StoreError::WrongTipHash);
        }
        let previous = self
            .transaction
            .query_row(
                "SELECT previous_tip_height, previous_tip_hash
                 FROM names_rollback_blocks WHERE height = ?1 AND hash = ?2",
                params![tip.height, expected_hash.as_slice()],
                |row| {
                    let height: Option<u32> = row.get(0)?;
                    let hash: Option<Vec<u8>> = row.get(1)?;
                    Ok((height, hash))
                },
            )
            .optional()?
            .ok_or(StoreError::MissingRollbackJournal)?;
        let previous_tip = decode_optional_tip(previous)?;

        let mut statement = self.transaction.prepare(
            "SELECT name_id, previous_record
             FROM names_rollback_heads WHERE block_height = ?1 ORDER BY name_id",
        )?;
        let changes = statement
            .query_map([tip.height], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<Vec<u8>>>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        for (name_id, previous) in changes {
            let name_id = decode_name_id(name_id)?;
            let previous = previous
                .map(|bytes| serde_json::from_slice::<HeadRecord>(&bytes))
                .transpose()?;
            if let Some(record) = &previous {
                validate_head(
                    name_id,
                    record,
                    self.identity.network,
                    previous_tip.map(|tip| tip.height),
                )?;
            }
            write_head(&self.transaction, name_id, previous.as_ref())?;
        }

        let mut statement = self.transaction.prepare(
            "SELECT height, tx_index, txid, previous_commitment
             FROM names_rollback_commits
             WHERE block_height = ?1 ORDER BY height, tx_index, txid",
        )?;
        let changes = statement
            .query_map([tip.height], |row| {
                Ok((
                    row.get::<_, u32>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        for (height, tx_index, txid, previous) in changes {
            let reference = CommitRef {
                height,
                tx_index,
                txid: decode_32(txid)?,
            };
            write_commit(
                &self.transaction,
                reference,
                previous.map(decode_32).transpose()?,
            )?;
        }

        self.transaction.execute(
            "DELETE FROM names_rollback_blocks WHERE height = ?1",
            [tip.height],
        )?;
        write_tip(&self.transaction, previous_tip)?;
        Ok(previous_tip)
    }

    /// Prunes only explicitly finalized rollback history while retaining the
    /// configured safe minimum behind the current tip.
    pub fn finalize_through(&mut self, height: u32) -> Result<(), StoreError> {
        let tip = read_tip(&self.transaction)?.ok_or(StoreError::FinalizationBeyondTip)?;
        if height > tip.height {
            return Err(StoreError::FinalizationBeyondTip);
        }
        let latest_safe = tip
            .height
            .checked_sub(self.identity.minimum_rollback_blocks)
            .ok_or(StoreError::InsufficientRollbackRetention)?;
        if height > latest_safe {
            return Err(StoreError::InsufficientRollbackRetention);
        }
        self.transaction.execute(
            "DELETE FROM names_rollback_blocks WHERE height <= ?1",
            [height],
        )?;
        self.transaction.execute(
            "UPDATE names_metadata
             SET finalized_height = CASE
                 WHEN finalized_height IS NULL OR finalized_height < ?1 THEN ?1
                 ELSE finalized_height
             END
             WHERE singleton = 1",
            [height],
        )?;
        Ok(())
    }
}

fn initialize_or_validate_metadata(
    connection: &Connection,
    identity: StoreIdentity,
) -> Result<(), StoreError> {
    let existing = connection
        .query_row(
            "SELECT schema_version, deployment_id, ruleset_fingerprint,
                    network, coverage_kind, coverage_name_id, minimum_rollback_blocks
             FROM names_metadata WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, u32>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, u8>(3)?,
                    row.get::<_, u8>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                    row.get::<_, u32>(6)?,
                ))
            },
        )
        .optional()?;
    let (coverage_kind, coverage_name_id) = encode_coverage(identity.coverage);
    let network = encode_network(identity.network);
    if let Some((schema, deployment, ruleset, stored_network, kind, name_id, retention)) = existing
    {
        if schema != SCHEMA_VERSION {
            return Err(StoreError::UnsupportedSchema { actual: schema });
        }
        if decode_32(deployment)? != identity.deployment_id
            || decode_32(ruleset)? != identity.ruleset_fingerprint
            || stored_network != network
        {
            return Err(StoreError::IdentityMismatch);
        }
        if kind != coverage_kind || name_id != coverage_name_id {
            return Err(StoreError::CoverageMismatch);
        }
        if retention != identity.minimum_rollback_blocks {
            return Err(StoreError::IdentityMismatch);
        }
        return Ok(());
    }
    connection.execute(
        "INSERT INTO names_metadata(
             singleton, schema_version, deployment_id, ruleset_fingerprint,
             network, coverage_kind, coverage_name_id, minimum_rollback_blocks
         ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            SCHEMA_VERSION,
            identity.deployment_id.as_slice(),
            identity.ruleset_fingerprint.as_slice(),
            network,
            coverage_kind,
            coverage_name_id,
            identity.minimum_rollback_blocks,
        ],
    )?;
    Ok(())
}

fn encode_coverage(coverage: Coverage) -> (u8, Option<Vec<u8>>) {
    match coverage {
        Coverage::Complete => (0, None),
        Coverage::Exact(name_id) => (1, Some(name_id.to_bytes().to_vec())),
        Coverage::Owned => (2, None),
    }
}

fn encode_network(network: Network) -> u8 {
    match network {
        Network::Main => 0,
        Network::Test => 1,
        Network::Regtest => 2,
    }
}

fn validate_head(
    name_id: NameId,
    record: &HeadRecord,
    network: Network,
    tip_height: Option<u32>,
) -> Result<(), StoreError> {
    let name = Name::parse(&record.name).map_err(|_| StoreError::InvalidStoredRecord)?;
    if name.id().map_err(|_| StoreError::InvalidStoredRecord)? != name_id {
        return Err(StoreError::InvalidStoredRecord);
    }
    CanonicalUa::parse(network, &record.ua).map_err(|_| StoreError::InvalidStoredRecord)?;
    FieldElement::from_bytes(record.commitment).map_err(|_| StoreError::InvalidStoredRecord)?;
    FieldElement::from_bytes(record.future_nf).map_err(|_| StoreError::InvalidStoredRecord)?;
    if record.expiry_height < record.producer.height
        || record
            .terminal_height
            .is_some_and(|height| height < record.producer.height)
        || tip_height.is_some_and(|tip| {
            record.producer.height > tip
                || record.terminal_height.is_some_and(|height| height > tip)
        })
    {
        return Err(StoreError::InvalidStoredRecord);
    }
    Ok(())
}

fn read_tip(connection: &Connection) -> Result<Option<ReducerTip>, StoreError> {
    let (height, hash) = connection.query_row(
        "SELECT tip_height, tip_hash FROM names_metadata WHERE singleton = 1",
        [],
        |row| {
            Ok((
                row.get::<_, Option<u32>>(0)?,
                row.get::<_, Option<Vec<u8>>>(1)?,
            ))
        },
    )?;
    decode_optional_tip((height, hash))
}

fn decode_optional_tip(
    value: (Option<u32>, Option<Vec<u8>>),
) -> Result<Option<ReducerTip>, StoreError> {
    match value {
        (None, None) => Ok(None),
        (Some(height), Some(hash)) => Ok(Some(ReducerTip {
            height,
            hash: decode_32(hash)?,
        })),
        _ => Err(StoreError::InvalidStoredRecord),
    }
}

fn write_tip(connection: &Connection, tip: Option<ReducerTip>) -> Result<(), StoreError> {
    connection.execute(
        "UPDATE names_metadata SET tip_height = ?1, tip_hash = ?2 WHERE singleton = 1",
        params![
            tip.map(|value| value.height),
            tip.map(|value| value.hash.to_vec()),
        ],
    )?;
    Ok(())
}

fn read_head(connection: &Connection, name_id: NameId) -> Result<Option<HeadRecord>, StoreError> {
    connection
        .query_row(
            "SELECT name, ua, producer_height, producer_tx_index, producer_txid,
                    producer_action_index, commitment, future_nf, producer_epoch,
                    expiry_height, terminal_height
             FROM names_heads WHERE name_id = ?1",
            [name_id.to_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u32>(2)?,
                    row.get::<_, u32>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, u32>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, u32>(8)?,
                    row.get::<_, u32>(9)?,
                    row.get::<_, Option<u32>>(10)?,
                ))
            },
        )
        .optional()?
        .map(|value| {
            Ok(HeadRecord {
                name: value.0,
                ua: value.1,
                producer: StateRef {
                    height: value.2,
                    tx_index: value.3,
                    txid: decode_32(value.4)?,
                    action_index: value.5,
                },
                commitment: decode_32(value.6)?,
                future_nf: decode_32(value.7)?,
                producer_epoch: value.8,
                expiry_height: value.9,
                terminal_height: value.10,
            })
        })
        .transpose()
}

fn write_head(
    connection: &Connection,
    name_id: NameId,
    record: Option<&HeadRecord>,
) -> Result<(), StoreError> {
    connection.execute(
        "DELETE FROM names_heads WHERE name_id = ?1",
        [name_id.to_bytes().as_slice()],
    )?;
    if let Some(record) = record {
        connection.execute(
            "INSERT INTO names_heads(
                 name_id, name, ua, producer_height, producer_tx_index,
                 producer_txid, producer_action_index, commitment, future_nf,
                 producer_epoch, expiry_height, terminal_height
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                name_id.to_bytes().as_slice(),
                record.name,
                record.ua,
                record.producer.height,
                record.producer.tx_index,
                record.producer.txid.as_slice(),
                record.producer.action_index,
                record.commitment.as_slice(),
                record.future_nf.as_slice(),
                record.producer_epoch,
                record.expiry_height,
                record.terminal_height,
            ],
        )?;
    }
    Ok(())
}

fn read_commit(
    connection: &Connection,
    reference: CommitRef,
) -> Result<Option<[u8; 32]>, StoreError> {
    connection
        .query_row(
            "SELECT commitment FROM names_pending_commits
             WHERE height = ?1 AND tx_index = ?2 AND txid = ?3",
            params![
                reference.height,
                reference.tx_index,
                reference.txid.as_slice()
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?
        .map(decode_32)
        .transpose()
}

fn write_commit(
    connection: &Connection,
    reference: CommitRef,
    commitment: Option<[u8; 32]>,
) -> Result<(), StoreError> {
    connection.execute(
        "DELETE FROM names_pending_commits
         WHERE height = ?1 AND tx_index = ?2 AND txid = ?3",
        params![
            reference.height,
            reference.tx_index,
            reference.txid.as_slice()
        ],
    )?;
    if let Some(commitment) = commitment {
        connection.execute(
            "INSERT INTO names_pending_commits(height, tx_index, txid, commitment)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                reference.height,
                reference.tx_index,
                reference.txid.as_slice(),
                commitment.as_slice(),
            ],
        )?;
    }
    Ok(())
}

fn decode_name_id(bytes: Vec<u8>) -> Result<NameId, StoreError> {
    NameId::from_bytes(decode_32(bytes)?).map_err(|_| StoreError::InvalidStoredRecord)
}

fn decode_32(bytes: Vec<u8>) -> Result<[u8; 32], StoreError> {
    bytes
        .try_into()
        .map_err(|_| StoreError::InvalidStoredRecord)
}

#[cfg(test)]
mod tests {
    use super::*;
    use coppice_names::{
        protocol::{CanonicalUa, FieldElement, Name, Network},
        reducer::{CommitChange, HeadChange},
    };

    const UA: &str = "uregtest1rxnn8qurdex552draeuvvvucggeknmmsxazg52mkatf0hrclhppe5jeqj6w7svqtxvxq320tw6ejsk4nm8zk8f35274vlwqerfx74904pydaxe27wnpq8llqxclaa0n04zg764ppzfruu4gsagmqw0mlvx";

    fn identity(coverage: Coverage) -> StoreIdentity {
        StoreIdentity {
            deployment_id: [1; 32],
            ruleset_fingerprint: [2; 32],
            network: Network::Regtest,
            coverage,
            minimum_rollback_blocks: 1,
        }
    }

    fn head() -> (NameId, Head) {
        let name = Name::parse("alice").unwrap();
        let name_id = name.id().unwrap();
        (
            name_id,
            Head {
                name,
                ua: CanonicalUa::parse(Network::Regtest, UA).unwrap(),
                producer: StateRef {
                    height: 10,
                    tx_index: 0,
                    txid: [3; 32],
                    action_index: 0,
                },
                commitment: FieldElement::from_bytes([4; 32]).unwrap(),
                future_nf: FieldElement::from_bytes([5; 32]).unwrap(),
                producer_epoch: 1,
                expiry_height: 20,
                terminal_height: None,
            },
        )
    }

    fn delta() -> StateDelta {
        let (name_id, head) = head();
        let commitment = Commitment::from_bytes([6; 32]).unwrap();
        StateDelta {
            from_tip: None,
            to_tip: Some(ReducerTip {
                height: 10,
                hash: [7; 32],
            }),
            heads: vec![HeadChange {
                name_id,
                previous: None,
                current: Some(head),
            }],
            commits: vec![CommitChange {
                reference: CommitRef {
                    height: 10,
                    tx_index: 1,
                    txid: [8; 32],
                },
                previous: None,
                current: Some(commitment),
            }],
        }
    }

    #[test]
    fn delta_commit_and_journal_rollback_round_trip() {
        let mut store = SqliteNamesStore::open_in_memory(identity(Coverage::Complete)).unwrap();
        let delta = delta();
        let name_id = delta.heads[0].name_id;
        store
            .with_transaction(|transaction| transaction.apply_delta(&delta))
            .unwrap();
        assert_eq!(store.tip().unwrap(), delta.to_tip);
        assert_eq!(
            store.head(name_id).unwrap(),
            delta.heads[0].current.as_ref().map(HeadRecord::from)
        );

        store
            .with_transaction(|transaction| {
                assert_eq!(transaction.rollback_tip([7; 32])?, None);
                Ok(())
            })
            .unwrap();
        assert_eq!(store.tip().unwrap(), None);
        assert_eq!(store.head(name_id).unwrap(), None);
    }

    #[test]
    fn injected_cross_layer_failure_rolls_back_every_write() {
        let mut store = SqliteNamesStore::open_in_memory(identity(Coverage::Complete)).unwrap();
        store
            .connection
            .execute(
                "CREATE TABLE wallet_scan_state(height INTEGER NOT NULL)",
                [],
            )
            .unwrap();
        let delta = delta();
        let result = store.with_transaction(|transaction| {
            transaction
                .connection()
                .execute("INSERT INTO wallet_scan_state(height) VALUES (10)", [])?;
            transaction.apply_delta(&delta)?;
            transaction.put_core_snapshot(b"staged-core")?;
            Err::<(), _>(StoreError::InjectedFailure)
        });
        assert!(matches!(result, Err(StoreError::InjectedFailure)));
        assert_eq!(store.tip().unwrap(), None);
        assert_eq!(
            store
                .connection
                .query_row("SELECT COUNT(*) FROM wallet_scan_state", [], |row| row
                    .get::<_, u32>(0))
                .unwrap(),
            0
        );
        let snapshot: Option<Vec<u8>> = store
            .connection
            .query_row("SELECT core_snapshot FROM names_metadata", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(snapshot, None);
    }

    #[test]
    fn deterministic_block_failure_can_commit_the_consistent_prefix() {
        let mut store = SqliteNamesStore::open_in_memory(identity(Coverage::Complete)).unwrap();
        store
            .connection
            .execute(
                "CREATE TABLE wallet_scan_state(height INTEGER NOT NULL)",
                [],
            )
            .unwrap();
        let first = delta();
        let second = StateDelta {
            from_tip: first.to_tip,
            to_tip: Some(ReducerTip {
                height: 11,
                hash: [9; 32],
            }),
            heads: Vec::new(),
            commits: Vec::new(),
        };

        store
            .with_transaction(|transaction| {
                transaction.with_block_savepoint(|block| {
                    block.apply_delta(&first)?;
                    block
                        .connection()
                        .execute("INSERT INTO wallet_scan_state(height) VALUES (10)", [])?;
                    Ok(())
                })?;
                let failed = transaction.with_block_savepoint(|block| {
                    block.apply_delta(&second)?;
                    block
                        .connection()
                        .execute("INSERT INTO wallet_scan_state(height) VALUES (11)", [])?;
                    Err::<(), _>(StoreError::InjectedFailure)
                });
                assert!(matches!(failed, Err(StoreError::InjectedFailure)));
                Ok(())
            })
            .unwrap();

        assert_eq!(store.tip().unwrap(), first.to_tip);
        let heights = store
            .connection
            .prepare("SELECT height FROM wallet_scan_state ORDER BY height")
            .unwrap()
            .query_map([], |row| row.get::<_, u32>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(heights, vec![10]);
    }

    #[test]
    fn panic_unwinds_and_rolls_back_the_outer_transaction() {
        let mut store = SqliteNamesStore::open_in_memory(identity(Coverage::Complete)).unwrap();
        let delta = delta();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = store.with_transaction(|transaction| -> Result<(), StoreError> {
                transaction.apply_delta(&delta)?;
                panic!("injected host panic");
            });
        }));
        assert!(result.is_err());
        assert_eq!(store.tip().unwrap(), None);
    }

    #[test]
    fn unsupported_schema_fails_closed_on_reopen() {
        let path = tempfile::NamedTempFile::new().unwrap();
        {
            let store = SqliteNamesStore::open(path.path(), identity(Coverage::Complete)).unwrap();
            store
                .connection
                .execute("UPDATE names_metadata SET schema_version = 99", [])
                .unwrap();
        }
        assert!(matches!(
            SqliteNamesStore::open(path.path(), identity(Coverage::Complete)),
            Err(StoreError::UnsupportedSchema { actual: 99 })
        ));
    }

    #[test]
    fn native_indexes_are_rebuildable_and_non_unique() {
        let mut store = SqliteNamesStore::open_in_memory(identity(Coverage::Complete)).unwrap();
        assert!(store.derived_indexes_present().unwrap());
        store
            .connection
            .execute("DROP INDEX names_heads_future_nf", [])
            .unwrap();
        assert!(!store.derived_indexes_present().unwrap());
        store.rebuild_derived_indexes().unwrap();
        assert!(store.derived_indexes_present().unwrap());

        let sql: String = store
            .connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE name = 'names_heads_future_nf'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!sql.to_ascii_uppercase().contains("UNIQUE"));
    }

    #[test]
    fn missing_authority_is_coverage_and_tip_bound() {
        let delta = delta();
        let requested = delta.heads[0].name_id;
        let other = Name::parse("bob").unwrap().id().unwrap();
        let mut store =
            SqliteNamesStore::open_in_memory(identity(Coverage::Exact(requested))).unwrap();
        store
            .with_transaction(|transaction| transaction.apply_delta(&delta))
            .unwrap();
        let tip = delta.to_tip.unwrap();
        assert_eq!(
            store.missing_authority(requested, tip).unwrap(),
            MissingAuthority::Authoritative
        );
        assert_eq!(
            store.missing_authority(other, tip).unwrap(),
            MissingAuthority::InsufficientCoverage
        );
        assert_eq!(
            store
                .missing_authority(
                    requested,
                    ReducerTip {
                        height: 11,
                        hash: [9; 32]
                    }
                )
                .unwrap(),
            MissingAuthority::StaleTip
        );
    }
}
