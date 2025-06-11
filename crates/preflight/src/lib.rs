// Copyright 2024-2025 RISC Zero, Inc.  (Apache-2.0)

use crate::client::PreflightClient;
use crate::driver::PreflightDriver;
use crate::provider::new_provider;
use alloy::network::Network;
use alloy::primitives::B256;
use anyhow::Context;
use log::info;
use provider::query::BlockQuery;
use reth_chainspec::NamedChain;
use std::path::PathBuf;
use tokio::task::spawn_blocking;
use zeth_core::driver::CoreDriver;
use zeth_core::rescue::Recoverable;
use zeth_core::serde_pot_compat::{HeaderPot, BlockPot};

use zeth_core::stateless::client::StatelessClient;
use zeth_core::stateless::data::{
    RkyvStatelessClientData, StatelessClientChainData, StatelessClientData,
};

use pot::Compatibility;

pub mod client;
pub mod db;
pub mod driver;
pub mod provider;

#[derive(Debug, Default, Clone)]
pub struct Witness {
    pub encoded_rkyv_input: Vec<u8>,
    pub encoded_chain_input: Vec<u8>,
    pub validated_tip_hash: B256,
    pub validated_tip_number: u64,
    pub validated_tail_hash: B256,
    pub validated_tail_number: u64,
    pub chain: NamedChain,
}

impl Witness {
    pub fn driver_from<R: CoreDriver>(data: &StatelessClientData<R::Block, R::Header>) -> Self {
        // ---------- slice-1 : rkyv ------------------------------------------------
        let rkyv_data = RkyvStatelessClientData::from(data.clone());
        let encoded_rkyv_input = rkyv::to_bytes::<rkyv::rancor::Error>(&rkyv_data)
            .expect("rkyv-ser")
            .to_vec();

        // -------- slice-2 : pot (legacy fixed-width ints) -----------------------
        let chain_data = StatelessClientChainData::<R::Block, R::Header>::from(data.clone());
        
        let mut pot_buf = Vec::with_capacity(4096);
        {
            // FULL compatibility + Config → restores pre-v3 integer encoding
            pot::Config::new()
                .compatibility(Compatibility::Full)
                .serialize_into(&chain_data, &mut pot_buf)
                .expect("pot serialize failed");
        }
        let encoded_chain_input = pot_buf;

        // -------------------------------------------------------------------------
        let tip = R::block_header(data.blocks.last().unwrap());
        let tail = &data.parent_header;
        Self {
            encoded_rkyv_input,
            encoded_chain_input,
            validated_tip_hash: R::header_hash(tip),
            validated_tip_number: R::block_number(tip),
            validated_tail_hash: R::header_hash(tail),
            validated_tail_number: R::block_number(tail),
            chain: data.chain,
        }
    }

    // Specialized version for Ethereum headers that can use HeaderPot
    pub fn driver_from_eth(data: &StatelessClientData<reth_primitives::Block, reth_primitives::Header>) -> Self {
        // ---------- slice-1 : rkyv ------------------------------------------------
        let rkyv_data = RkyvStatelessClientData::from(data.clone());
        let encoded_rkyv_input = rkyv::to_bytes::<rkyv::rancor::Error>(&rkyv_data)
            .expect("rkyv-ser")
            .to_vec();

        // -------- slice-2 : pot (legacy fixed-width ints) -----------------------
        // HERE USE CUSTOM SERIALIZER FOR POT HEADER AND BLOCKS
        // use here chaindata with substituted pot headers and blocks
        let original_chain_data = StatelessClientChainData::<reth_primitives::Block, reth_primitives::Header>::from(data.clone());
        
        // Convert to full BlockPot-compatible chain data for complete POT fix
        let chain_data: StatelessClientChainData<BlockPot, HeaderPot> = StatelessClientChainData {
            blocks: original_chain_data.blocks.into_iter().map(BlockPot::from).collect(),
            parent_header: HeaderPot::from(original_chain_data.parent_header),
            ancestor_headers: original_chain_data.ancestor_headers.into_iter().map(HeaderPot::from).collect(),
        };

        let mut pot_buf = Vec::with_capacity(4096);
        {
            // FULL compatibility + Config → restores pre-v3 integer encoding
            pot::Config::new()
                .compatibility(Compatibility::Full)
                .serialize_into(&chain_data, &mut pot_buf)
                .expect("pot serialize failed");
        }
        let encoded_chain_input = pot_buf;

        // -------------------------------------------------------------------------
        let tip = &data.blocks.last().unwrap().header;
        let tail = &data.parent_header;
        Self {
            encoded_rkyv_input,
            encoded_chain_input,
            validated_tip_hash: tip.hash_slow(),
            validated_tip_number: tip.number,
            validated_tail_hash: tail.hash_slow(),
            validated_tail_number: tail.number,
            chain: data.chain,
        }
    }
}

#[async_trait::async_trait]
pub trait BlockBuilder<N, D, R, P>
where
    N: Network,
    D: Recoverable + 'static,
    R: CoreDriver + Clone + 'static,
    <R as CoreDriver>::Block: Send + 'static,
    <R as CoreDriver>::Header: Send + 'static,
    P: PreflightDriver<R, N> + Clone + 'static,
{
    type PreflightClient: PreflightClient<N, R, P>;
    type StatelessClient: StatelessClient<R, D>;

    // ----------------------------------------------------------------------
    async fn build_blocks(
        chain_id: Option<u64>,
        cache_dir: Option<PathBuf>,
        rpc_url: Option<String>,
        block_number: u64,
        block_count: u64,
    ) -> anyhow::Result<Witness> {
        let preflight: StatelessClientData<R::Block, R::Header> = spawn_blocking(move || {
            <Self::PreflightClient>::preflight(
                chain_id,
                cache_dir,
                rpc_url,
                block_number,
                block_count,
            )
        })
        .await??;

        let witness = Witness::driver_from::<R>(&preflight);

        info!(
            "Running from memory (input size: {} bytes)…",
            witness.encoded_rkyv_input.len() + witness.encoded_chain_input.len()
        );

        let round_trip: StatelessClientData<R::Block, R::Header> =
            Self::StatelessClient::data_from_parts(
                &witness.encoded_rkyv_input,
                &witness.encoded_chain_input,
            )
            .context("deserialization failed")?;

        Self::StatelessClient::validate(round_trip).context("validation failed")?;

        info!("Memory run successful; input generation complete.");
        Ok(witness)
    }

    // ----------------------------------------------------------------------
    async fn build_journal(
        chain_id: Option<u64>,
        cache_dir: Option<PathBuf>,
        rpc_url: Option<String>,
        block_number: u64,
        block_count: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let tip_no = block_number + block_count - 1;

        let (tip_block, chain, client_ver) = spawn_blocking(move || {
            let provider = new_provider::<N>(cache_dir, block_number, rpc_url, chain_id).unwrap();
            let mut p = provider.borrow_mut();

            let tip = p.get_full_block(&BlockQuery { block_no: tip_no }).unwrap();
            let ver = p.get_client_version().unwrap();
            let chain = p.get_chain().unwrap() as u64;
            p.save().unwrap();
            (tip, chain, ver)
        })
        .await?;

        info!("Connected to provider (client {client_ver})");

        let header = P::derive_header_response(tip_block);
        let total_diff = P::total_difficulty(&header).unwrap_or_default();
        let final_diff = R::final_difficulty(
            tip_no,
            total_diff,
            R::chain_spec(&chain.try_into().unwrap())
                .expect("unsupported chain")
                .as_ref(),
        );

        let journal = [
            chain.to_be_bytes().as_slice(),
            R::header_hash(&P::derive_header(header)).0.as_slice(),
            final_diff.to_be_bytes::<32>().as_slice(),
            block_count.to_be_bytes().as_slice(),
        ]
        .concat();

        info!("Final chain difficulty: {final_diff}");
        Ok(journal)
    }
}

// Ethereum-specific BlockBuilder that uses HeaderPot serialization
#[async_trait::async_trait]
pub trait EthBlockBuilder<N, D, R, P>
where
    N: Network,
    D: Recoverable + 'static,
    R: CoreDriver<Block = reth_primitives::Block, Header = reth_primitives::Header> + Clone + 'static,
    P: PreflightDriver<R, N> + Clone + 'static,
{
    type PreflightClient: PreflightClient<N, R, P>;
    type StatelessClient: StatelessClient<R, D>;

    // ----------------------------------------------------------------------
    async fn build_blocks_eth(
        chain_id: Option<u64>,
        cache_dir: Option<PathBuf>,
        rpc_url: Option<String>,
        block_number: u64,
        block_count: u64,
    ) -> anyhow::Result<Witness> {
        let preflight: StatelessClientData<reth_primitives::Block, reth_primitives::Header> = spawn_blocking(move || {
            <Self::PreflightClient>::preflight(
                chain_id,
                cache_dir,
                rpc_url,
                block_number,
                block_count,
            )
        })
        .await??;

        // Use HeaderPot serialization for Ethereum
        let witness = Witness::driver_from_eth(&preflight);

        info!(
            "Running from memory (input size: {} bytes)…",
            witness.encoded_rkyv_input.len() + witness.encoded_chain_input.len()
        );

        // Use HeaderPot deserialization for Ethereum
        let round_trip: StatelessClientData<reth_primitives::Block, reth_primitives::Header> =
            Self::StatelessClient::data_from_parts_eth(
                &witness.encoded_rkyv_input,
                &witness.encoded_chain_input,
            )
            .context("deserialization failed")?;

        Self::StatelessClient::validate(round_trip).context("validation failed")?;

        info!("Memory run successful; input generation complete.");
        Ok(witness)
    }

    // ----------------------------------------------------------------------
    async fn build_journal_eth(
        chain_id: Option<u64>,
        cache_dir: Option<PathBuf>,
        rpc_url: Option<String>,
        block_number: u64,
        block_count: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let tip_no = block_number + block_count - 1;

        let (tip_block, chain, client_ver) = spawn_blocking(move || {
            let provider = new_provider::<N>(cache_dir, block_number, rpc_url, chain_id).unwrap();
            let mut p = provider.borrow_mut();

            let tip = p.get_full_block(&BlockQuery { block_no: tip_no }).unwrap();
            let ver = p.get_client_version().unwrap();
            let chain = p.get_chain().unwrap() as u64;
            p.save().unwrap();
            (tip, chain, ver)
        })
        .await?;

        info!("Connected to provider (client {client_ver})");

        let header = P::derive_header_response(tip_block);
        let total_diff = P::total_difficulty(&header).unwrap_or_default();
        let final_diff = R::final_difficulty(
            tip_no,
            total_diff,
            R::chain_spec(&chain.try_into().unwrap())
                .expect("unsupported chain")
                .as_ref(),
        );

        let journal = [
            chain.to_be_bytes().as_slice(),
            R::header_hash(&P::derive_header(header)).0.as_slice(),
            final_diff.to_be_bytes::<32>().as_slice(),
            block_count.to_be_bytes().as_slice(),
        ]
        .concat();

        info!("Final chain difficulty: {final_diff}");
        Ok(journal)
    }
}
