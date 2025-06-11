use anyhow::{Context, Result};
use clap::Parser;
use reth_primitives::TxType;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Ethereum RPC endpoint URL
    #[arg(short, long, default_value = "https://ethereum-rpc.publicnode.com")]
    rpc_url: String,
    
    /// Number of recent blocks to analyze
    #[arg(short, long, default_value = "1000")]
    blocks: u64,
}

#[derive(Debug, Serialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    params: serde_json::Value,
    id: u64,
}

#[derive(Debug, Deserialize)]
struct JsonRpcResponse<T> {
    jsonrpc: String,
    result: Option<T>,
    error: Option<JsonRpcError>,
    id: u64,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i32,
    message: String,
}

#[derive(Debug, Deserialize)]
struct Block {
    number: String,
    hash: String,
    transactions: Vec<Transaction>,
    #[serde(rename = "blobGasUsed")]
    blob_gas_used: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Transaction {
    #[serde(rename = "type")]
    tx_type: Option<String>,
    hash: String,
}

impl JsonRpcRequest {
    fn new(method: &str, params: serde_json::Value, id: u64) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params,
            id,
        }
    }
}

struct EthereumRpcClient {
    client: Client,
    rpc_url: String,
    request_id: std::sync::atomic::AtomicU64,
}

impl EthereumRpcClient {
    fn new(rpc_url: String) -> Self {
        Self {
            client: Client::new(),
            rpc_url,
            request_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    async fn call<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T> {
        let id = self.request_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let request = JsonRpcRequest::new(method, params, id);
        
        let response = self
            .client
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await
            .context("Failed to send RPC request")?;

        let rpc_response: JsonRpcResponse<T> = response
            .json()
            .await
            .context("Failed to parse RPC response")?;

        if let Some(error) = rpc_response.error {
            anyhow::bail!("RPC error {}: {}", error.code, error.message);
        }

        rpc_response.result.context("Missing result in RPC response")
    }

    async fn get_latest_block_number(&self) -> Result<u64> {
        let result: String = self
            .call("eth_blockNumber", serde_json::Value::Array(vec![]))
            .await?;
        
        let block_number = u64::from_str_radix(&result[2..], 16)
            .context("Failed to parse block number")?;
        
        Ok(block_number)
    }

    async fn get_block(&self, block_number: u64) -> Result<Block> {
        let params = serde_json::json!([
            format!("0x{:x}", block_number),
            true // include transactions
        ]);
        
        self.call("eth_getBlockByNumber", params).await
    }
}

#[derive(Debug)]
struct AnalysisResult {
    total_blocks: u64,
    blocks_without_eip4844: u64,
    blocks_with_eip4844: u64,
    total_eip4844_transactions: u64,
    block_range: (u64, u64),
    blocks_without_eip4844_list: Vec<u64>,
}

impl AnalysisResult {
    fn print_summary(&self) {
        println!("\n=== EIP-4844 Analysis Results ===");
        println!("Block range: {} - {}", self.block_range.0, self.block_range.1);
        println!("Total blocks analyzed: {}", self.total_blocks);
        println!("Blocks WITHOUT EIP-4844 transactions: {}", self.blocks_without_eip4844);
        println!("Blocks WITH EIP-4844 transactions: {}", self.blocks_with_eip4844);
        println!("Total EIP-4844 transactions found: {}", self.total_eip4844_transactions);
        
        let percentage_without = (self.blocks_without_eip4844 as f64 / self.total_blocks as f64) * 100.0;
        let percentage_with = (self.blocks_with_eip4844 as f64 / self.total_blocks as f64) * 100.0;
        
        println!("\nPercentages:");
        println!("  {:.2}% of blocks have NO EIP-4844 transactions", percentage_without);
        println!("  {:.2}% of blocks have EIP-4844 transactions", percentage_with);
        
        if self.blocks_with_eip4844 > 0 {
            let avg_tx_per_block = self.total_eip4844_transactions as f64 / self.blocks_with_eip4844 as f64;
            println!("  Average EIP-4844 transactions per block (with EIP-4844): {:.2}", avg_tx_per_block);
        }
        
        // Print blocks without EIP-4844 transactions in one line
        if !self.blocks_without_eip4844_list.is_empty() {
            println!("\nBlocks without EIP-4844 transactions: {}", 
                self.blocks_without_eip4844_list.iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<String>>()
                    .join(", "));
        }
    }
}

async fn analyze_blocks(client: &EthereumRpcClient, start_block: u64, num_blocks: u64) -> Result<AnalysisResult> {
    let mut blocks_without_eip4844 = 0;
    let mut blocks_with_eip4844 = 0;
    let mut total_eip4844_transactions = 0;
    let mut blob_gas_usage = HashMap::new();
    let mut blocks_without_eip4844_list = Vec::new();

    println!("Analyzing {} blocks starting from block {}...", num_blocks, start_block);
    
    for i in 0..num_blocks {
        let block_number = start_block - i;
        
        if i % 100 == 0 {
            println!("Progress: {}/{} blocks analyzed", i, num_blocks);
        }
        
        match client.get_block(block_number).await {
            Ok(block) => {
                let mut eip4844_count = 0;
                
                for tx in &block.transactions {
                    // EIP-4844 transactions have type "0x3"
                    if let Some(tx_type) = &tx.tx_type {
                        if tx_type == "0x3" {
                            eip4844_count += 1;
                            total_eip4844_transactions += 1;
                        }
                    }
                }
                
                if eip4844_count > 0 {
                    blocks_with_eip4844 += 1;
                    if let Some(blob_gas) = &block.blob_gas_used {
                        if let Ok(gas_used) = u64::from_str_radix(&blob_gas[2..], 16) {
                            blob_gas_usage.insert(block_number, gas_used);
                        }
                    }
                } else {
                    blocks_without_eip4844 += 1;
                    blocks_without_eip4844_list.push(block_number);
                }
            }
            Err(e) => {
                eprintln!("Warning: Failed to fetch block {}: {}", block_number, e);
                // Continue with other blocks
            }
        }
    }
    
    println!("Analysis complete!");
    
    Ok(AnalysisResult {
        total_blocks: num_blocks,
        blocks_without_eip4844,
        blocks_with_eip4844,
        total_eip4844_transactions,
        block_range: (start_block - num_blocks + 1, start_block),
        blocks_without_eip4844_list,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    
    println!("EIP-4844 Block Analyzer");
    println!("RPC URL: {}", args.rpc_url);
    println!("Blocks to analyze: {}", args.blocks);
    
    let client = EthereumRpcClient::new(args.rpc_url);
    
    // Get the latest block number
    println!("Fetching latest block number...");
    let latest_block = client.get_latest_block_number().await
        .context("Failed to get latest block number")?;
    
    println!("Latest block: {}", latest_block);
    
    // Analyze the requested number of recent blocks
    let result = analyze_blocks(&client, latest_block, args.blocks).await?;
    
    // Print results
    result.print_summary();
    
    Ok(())
} 