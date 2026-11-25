//! CIP-0112 Token Standard V2 CLI (`canton-rs token`, `S-DX-008`).
//!
//! Covers:
//! - `token faucet <party> <amount>` (`AmuletRules_DevNet_Tap`)
//! - `token create --instrument <I> --admin <party>`
//! - `token mint <instrument> <party> <amount>`
//! - `token transfer <instrument> <from> <to> <amount> [--auto-accept]`
//! - `token transfer accept|reject|withdraw <instruction>`
//! - `token balance <party> [instrument]`, `token balances`
//! - `token allocation create|list|withdraw|cancel`
//! - `token settle <batch>`
//! - `token activity <party>`

pub mod amulet;
pub mod client;
pub mod decimal;
pub mod settlement;
pub mod v2;

use std::path::PathBuf;

use clap::{Args, Subcommand};
use serde_json::Value as Json;

use self::amulet::cmd_faucet;
use self::client::{ConnArgs, OutputFormat, TokenClient};
use self::settlement::{
    cmd_allocation_abort, cmd_allocation_create, cmd_allocation_list, cmd_settle,
    AllocationCreateSpec,
};
use self::v2::{
    cmd_activity, cmd_balance, cmd_balances, cmd_create, cmd_mint, cmd_transfer,
    cmd_transfer_action, TransferSpec,
};

/// Top-level `canton-rs token` arguments.
#[derive(Args, Debug, Clone)]
pub struct TokenArgs {
    #[command(subcommand)]
    pub command: TokenCommand,
}

/// Token Standard V2 subcommands (`S-DX-008`).
#[derive(Subcommand, Debug, Clone)]
pub enum TokenCommand {
    /// Tap DevNet Amulet for `<party>` via `AmuletRules_DevNet_Tap`.
    Faucet(FaucetArgs),

    /// Upload V2 DAR, verify vetting, and initialize `TokenRules` for an instrument.
    Create(CreateTokenArgs),

    /// Mint `<amount>` of `<instrument>` to `<party>` via `TokenRules_OfferMint` + `Accept`.
    Mint(MintArgs),

    /// Transfer `<instrument>` holdings or accept/reject/withdraw a pending `TransferInstruction`.
    Transfer(Box<TransferArgs>),

    /// Show `(available, locked, total)` balance for `<party>` (optionally filtered by `[instrument]`).
    Balance(BalanceArgs),

    /// Show `(available, locked, total)` balances and total supplies across local parties.
    Balances(BalancesArgs),

    /// Manage DvP allocations (`create`, `list`, `withdraw`, `cancel`).
    Allocation(AllocationArgs),

    /// Atomically settle a DvP batch via `SettlementFactory_SettleBatch`.
    Settle(SettleArgs),

    /// Query `EventLog` and Token Standard V2 activity for `<party>`.
    Activity(ActivityArgs),
}

#[derive(Args, Debug, Clone)]
pub struct FaucetArgs {
    #[command(flatten)]
    pub conn: ConnArgs,
    /// Receiver party ID or unique hint.
    pub party: String,
    /// Decimal amount (`Numeric 10`) to tap.
    pub amount: String,
    /// Optional DSO party hint override when querying local ACS without `--scan-url`.
    #[arg(long)]
    pub dso: Option<String>,
    /// Optional `splice-amulet` DAR path override.
    #[arg(long)]
    pub dar: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct CreateTokenArgs {
    #[command(flatten)]
    pub conn: ConnArgs,
    /// Instrument identifier (e.g. `USDX`).
    #[arg(long)]
    pub instrument: String,
    /// Instrument admin party ID or hint.
    #[arg(long)]
    pub admin: String,
    /// Optional V2 test-token DAR path override.
    #[arg(long)]
    pub dar: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct MintArgs {
    #[command(flatten)]
    pub conn: ConnArgs,
    /// Instrument identifier.
    pub instrument: String,
    /// Recipient party ID or hint.
    pub party: String,
    /// Decimal amount (`Numeric 10`).
    pub amount: String,
    /// Optional admin party override.
    #[arg(long)]
    pub admin: Option<String>,
    /// Optional V2 DAR path override.
    #[arg(long)]
    pub dar: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
#[command(subcommand_precedence_over_arg = true)]
pub struct TransferArgs {
    #[command(flatten)]
    pub conn: ConnArgs,

    #[command(subcommand)]
    pub action: Option<TransferAction>,

    /// Instrument identifier (when initiating a transfer).
    pub instrument: Option<String>,
    /// Sender party ID or hint.
    pub from: Option<String>,
    /// Receiver party ID or hint.
    pub to: Option<String>,
    /// Decimal transfer amount (`Numeric 10`).
    pub amount: Option<String>,

    /// Immediately accept the created `TransferInstruction` as `<to>`.
    #[arg(long)]
    pub auto_accept: bool,

    /// Optional instrument admin party override.
    #[arg(long)]
    pub admin: Option<String>,

    /// Instruction expiry horizon in seconds (default 3600).
    #[arg(long, default_value_t = 3600)]
    pub expires_secs: u64,

    /// Optional V2 DAR path override.
    #[arg(long)]
    pub dar: Option<PathBuf>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum TransferAction {
    /// Accept a pending `TransferInstruction`.
    Accept(TransferActionArgs),
    /// Reject a pending `TransferInstruction` (restores sender holdings).
    Reject(TransferActionArgs),
    /// Withdraw a pending `TransferInstruction` (restores sender holdings).
    Withdraw(TransferActionArgs),
}

#[derive(Args, Debug, Clone)]
pub struct TransferActionArgs {
    #[command(flatten)]
    pub conn: ConnArgs,
    /// Target `TransferInstruction` contract ID.
    pub instruction: String,
    /// Acting party override (defaults to receiver for accept/reject, sender for withdraw).
    #[arg(long)]
    pub actor: Option<String>,
    /// Optional instrument admin override.
    #[arg(long)]
    pub admin: Option<String>,
    /// Optional V2 DAR path override.
    #[arg(long)]
    pub dar: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct BalanceArgs {
    #[command(flatten)]
    pub conn: ConnArgs,
    /// Owner party ID or hint.
    pub party: String,
    /// Optional instrument filter.
    pub instrument: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct BalancesArgs {
    #[command(flatten)]
    pub conn: ConnArgs,
    /// Specific party filters (repeatable; defaults to all local parties).
    #[arg(long = "party")]
    pub parties: Vec<String>,
    /// Optional instrument filter.
    #[arg(long)]
    pub instrument: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct AllocationArgs {
    #[command(subcommand)]
    pub command: AllocationCommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum AllocationCommand {
    /// Allocate holdings toward a DvP settlement batch (`AllocationFactory_Allocate`).
    Create(AllocationCreateArgs),
    /// List active `AllocationV2` contracts.
    List(AllocationListArgs),
    /// Withdraw an allocation (`Allocation_Withdraw`).
    Withdraw(AllocationAbortArgs),
    /// Cancel an allocation as executor (`Allocation_Cancel`).
    Cancel(AllocationAbortArgs),
}

#[derive(Args, Debug, Clone)]
pub struct AllocationCreateArgs {
    #[command(flatten)]
    pub conn: ConnArgs,
    /// Settlement batch ID.
    #[arg(long)]
    pub settlement_id: String,
    /// Settlement executor party ID or hint.
    #[arg(long)]
    pub executor: String,
    /// Allocation authorizer party ID or hint.
    #[arg(long)]
    pub authorizer: String,
    /// Optional instrument admin party override.
    #[arg(long)]
    pub admin: Option<String>,
    /// Leg side spec: `<leg_id>:<sender|receiver>:<otherside>:<instrument>:<amount>` (repeatable).
    #[arg(long = "leg")]
    pub legs: Vec<String>,
    /// Settlement deadline horizon in seconds (default 3600).
    #[arg(long, default_value_t = 3600)]
    pub deadline_secs: u64,
    /// Optional V2 DAR path override.
    #[arg(long)]
    pub dar: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct AllocationListArgs {
    #[command(flatten)]
    pub conn: ConnArgs,
    /// Optional party filter.
    #[arg(long)]
    pub party: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct AllocationAbortArgs {
    #[command(flatten)]
    pub conn: ConnArgs,
    /// Target `AllocationV2` contract ID.
    pub allocation: String,
    /// Acting party override.
    #[arg(long)]
    pub actor: Option<String>,
    /// Optional V2 DAR path override.
    #[arg(long)]
    pub dar: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct SettleArgs {
    #[command(flatten)]
    pub conn: ConnArgs,
    /// Settlement batch ID.
    pub batch: String,
    /// Executor party ID or hint.
    #[arg(long)]
    pub executor: Option<String>,
    /// Allocation contract IDs participating in this settlement (repeatable; auto-discovered by batch if omitted).
    #[arg(long = "alloc")]
    pub allocs: Vec<String>,
    /// Explicit leg specs `<leg_id>:<sender>:<receiver>:<instrument>:<amount>` (optional when allocations encode all legs).
    #[arg(long = "leg")]
    pub legs: Vec<String>,
    /// Optional admin party override.
    #[arg(long)]
    pub admin: Option<String>,
    /// Optional V2 DAR path override.
    #[arg(long)]
    pub dar: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct ActivityArgs {
    #[command(flatten)]
    pub conn: ConnArgs,
    /// Party ID or hint.
    pub party: String,
    /// Exclusive start offset (default 0).
    #[arg(long)]
    pub from: Option<u64>,
    /// Inclusive end offset (default current ledger-end).
    #[arg(long)]
    pub to: Option<u64>,
}

/// Entrypoint for `canton-rs token ...`.
pub fn execute_token(args: TokenArgs) -> Result<(), String> {
    match args.command {
        TokenCommand::Faucet(a) => {
            let client = TokenClient::connect(&a.conn)?;
            let out = cmd_faucet(
                &client,
                &a.party,
                &a.amount,
                a.dso.as_deref(),
                a.dar.as_deref(),
            )?;
            print_output(a.conn.format, &out)?;
        }
        TokenCommand::Create(a) => {
            let client = TokenClient::connect(&a.conn)?;
            let out = cmd_create(&client, &a.instrument, &a.admin, a.dar.as_deref())?;
            print_output(a.conn.format, &out)?;
        }
        TokenCommand::Mint(a) => {
            let client = TokenClient::connect(&a.conn)?;
            let out = cmd_mint(
                &client,
                &a.instrument,
                &a.party,
                &a.amount,
                a.admin.as_deref(),
                a.dar.as_deref(),
            )?;
            print_output(a.conn.format, &out)?;
        }
        TokenCommand::Transfer(a) => {
            let a = *a;
            match a.action {
                Some(TransferAction::Accept(act)) => {
                    let conn = pick_conn(&act.conn, &a.conn);
                    let client = TokenClient::connect(&conn)?;
                    let out = cmd_transfer_action(
                        &client,
                        "accept",
                        &act.instruction,
                        act.actor.as_deref(),
                        act.admin.as_deref().or(a.admin.as_deref()),
                        act.dar.as_deref().or(a.dar.as_deref()),
                    )?;
                    print_output(conn.format, &out)?;
                }
                Some(TransferAction::Reject(act)) => {
                    let conn = pick_conn(&act.conn, &a.conn);
                    let client = TokenClient::connect(&conn)?;
                    let out = cmd_transfer_action(
                        &client,
                        "reject",
                        &act.instruction,
                        act.actor.as_deref(),
                        act.admin.as_deref().or(a.admin.as_deref()),
                        act.dar.as_deref().or(a.dar.as_deref()),
                    )?;
                    print_output(conn.format, &out)?;
                }
                Some(TransferAction::Withdraw(act)) => {
                    let conn = pick_conn(&act.conn, &a.conn);
                    let client = TokenClient::connect(&conn)?;
                    let out = cmd_transfer_action(
                        &client,
                        "withdraw",
                        &act.instruction,
                        act.actor.as_deref(),
                        act.admin.as_deref().or(a.admin.as_deref()),
                        act.dar.as_deref().or(a.dar.as_deref()),
                    )?;
                    print_output(conn.format, &out)?;
                }
                None => {
                    let (Some(inst), Some(from), Some(to), Some(amount)) =
                        (a.instrument, a.from, a.to, a.amount)
                    else {
                        return Err(
                        "usage: token transfer <instrument> <from> <to> <amount> OR token transfer accept|reject|withdraw <instruction>"
                            .to_string(),
                    );
                    };
                    let client = TokenClient::connect(&a.conn)?;
                    let out = cmd_transfer(
                        &client,
                        &TransferSpec {
                            instrument: &inst,
                            from: &from,
                            to: &to,
                            amount: &amount,
                            auto_accept: a.auto_accept,
                            admin_opt: a.admin.as_deref(),
                            expires_secs: a.expires_secs,
                            dar_override: a.dar.as_deref(),
                        },
                    )?;
                    print_output(a.conn.format, &out)?;
                }
            }
        }
        TokenCommand::Balance(a) => {
            let client = TokenClient::connect(&a.conn)?;
            let out = cmd_balance(&client, &a.party, a.instrument.as_deref())?;
            print_output(a.conn.format, &out)?;
        }
        TokenCommand::Balances(a) => {
            let client = TokenClient::connect(&a.conn)?;
            let out = cmd_balances(&client, &a.parties, a.instrument.as_deref())?;
            print_output(a.conn.format, &out)?;
        }
        TokenCommand::Allocation(a) => match a.command {
            AllocationCommand::Create(c) => {
                let client = TokenClient::connect(&c.conn)?;
                let out = cmd_allocation_create(
                    &client,
                    &AllocationCreateSpec {
                        settlement_id: &c.settlement_id,
                        executor: &c.executor,
                        authorizer: &c.authorizer,
                        admin_opt: c.admin.as_deref(),
                        raw_legs: &c.legs,
                        deadline_secs: c.deadline_secs,
                        dar_override: c.dar.as_deref(),
                    },
                )?;
                print_output(c.conn.format, &out)?;
            }
            AllocationCommand::List(l) => {
                let client = TokenClient::connect(&l.conn)?;
                let out = cmd_allocation_list(&client, l.party.as_deref())?;
                print_output(l.conn.format, &out)?;
            }
            AllocationCommand::Withdraw(w) => {
                let client = TokenClient::connect(&w.conn)?;
                let out = cmd_allocation_abort(
                    &client,
                    "withdraw",
                    &w.allocation,
                    w.actor.as_deref(),
                    w.dar.as_deref(),
                )?;
                print_output(w.conn.format, &out)?;
            }
            AllocationCommand::Cancel(c) => {
                let client = TokenClient::connect(&c.conn)?;
                let out = cmd_allocation_abort(
                    &client,
                    "cancel",
                    &c.allocation,
                    c.actor.as_deref(),
                    c.dar.as_deref(),
                )?;
                print_output(c.conn.format, &out)?;
            }
        },
        TokenCommand::Settle(a) => {
            let client = TokenClient::connect(&a.conn)?;
            let out = cmd_settle(
                &client,
                &a.batch,
                a.executor.as_deref(),
                &a.allocs,
                &a.legs,
                a.admin.as_deref(),
                a.dar.as_deref(),
            )?;
            print_output(a.conn.format, &out)?;
        }
        TokenCommand::Activity(a) => {
            let client = TokenClient::connect(&a.conn)?;
            let out = cmd_activity(&client, &a.party, a.from, a.to)?;
            print_output(a.conn.format, &out)?;
        }
    }
    Ok(())
}

fn pick_conn(sub: &ConnArgs, parent: &ConnArgs) -> ConnArgs {
    let user = if sub.user != "participant_admin" {
        sub.user.clone()
    } else {
        parent.user.clone()
    };
    let format = if sub.format != OutputFormat::Text {
        sub.format
    } else {
        parent.format
    };
    ConnArgs {
        name: sub.name.clone().or_else(|| parent.name.clone()),
        state_dir: sub.state_dir.clone().or_else(|| parent.state_dir.clone()),
        participant: sub
            .participant
            .clone()
            .or_else(|| parent.participant.clone()),
        url: sub.url.clone().or_else(|| parent.url.clone()),
        token: sub.token.clone().or_else(|| parent.token.clone()),
        user,
        scan_url: sub.scan_url.clone().or_else(|| parent.scan_url.clone()),
        synchronizer: sub
            .synchronizer
            .clone()
            .or_else(|| parent.synchronizer.clone()),
        format,
    }
}

fn print_output(format: OutputFormat, val: &Json) -> Result<(), String> {
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(val).map_err(|e| e.to_string())?
            );
        }
        OutputFormat::Text => {
            print_text(val);
        }
    }
    Ok(())
}

fn print_text(val: &Json) {
    let action = val["action"].as_str().unwrap_or("token");
    match action {
        "balance" => {
            println!("Balances for {}", val["party"].as_str().unwrap_or(""));
            if let Some(rows) = val["balances"].as_array() {
                if rows.is_empty() {
                    println!("  (none)");
                }
                for r in rows {
                    println!(
                        "  {} avail={} locked={} total={} (admin={})",
                        r["instrument"].as_str().unwrap_or(""),
                        r["available"].as_str().unwrap_or("0.0"),
                        r["locked"].as_str().unwrap_or("0.0"),
                        r["total"].as_str().unwrap_or("0.0"),
                        r["admin"].as_str().unwrap_or(""),
                    );
                }
            }
        }
        "balances" => {
            if let Some(rows) = val["balances"].as_array() {
                for r in rows {
                    println!(
                        "{}\t{}\tavail={}\tlocked={}\ttotal={}",
                        r["party"].as_str().unwrap_or(""),
                        r["instrument"].as_str().unwrap_or(""),
                        r["available"].as_str().unwrap_or("0.0"),
                        r["locked"].as_str().unwrap_or("0.0"),
                        r["total"].as_str().unwrap_or("0.0"),
                    );
                }
            }
            if let Some(supplies) = val["supplies"].as_array() {
                for s in supplies {
                    println!(
                        "SUPPLY\t{}\t{}",
                        s["instrument"].as_str().unwrap_or(""),
                        s["supply"].as_str().unwrap_or("0.0"),
                    );
                }
            }
        }
        "allocation list" => {
            if let Some(rows) = val["allocations"].as_array() {
                for r in rows {
                    println!(
                        "{}\tsettlement={}\tauthorizer={}",
                        r["allocation_cid"].as_str().unwrap_or(""),
                        r["settlement_id"].as_str().unwrap_or(""),
                        r["authorizer"].as_str().unwrap_or(""),
                    );
                }
            }
        }
        "activity" => {
            if let Some(events) = val["events"].as_array() {
                for ev in events {
                    println!(
                        "@{}\t{}\t{}\t{}",
                        ev["offset"].as_u64().unwrap_or(0),
                        ev["update_id"].as_str().unwrap_or(""),
                        ev["choice"].as_str().unwrap_or(""),
                        ev["contract_id"].as_str().unwrap_or(""),
                    );
                }
            }
        }
        _ => {
            println!("{}", serde_json::to_string_pretty(val).unwrap_or_default());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AllocationCommand, TokenArgs, TokenCommand, TransferAction};
    use clap::Parser;

    #[derive(Parser)]
    struct Wrapper {
        #[command(flatten)]
        token: TokenArgs,
    }

    #[test]
    fn cli_parses_transfer_positional_and_action_subcommands() {
        let positional = Wrapper::try_parse_from([
            "token",
            "transfer",
            "--name",
            "inst1",
            "--auto-accept",
            "USDX",
            "Alice",
            "Bob",
            "30.0",
        ])
        .expect("parse positional transfer");
        let TokenCommand::Transfer(t) = positional.token.command else {
            panic!("expected Transfer");
        };
        assert!(t.action.is_none());
        assert!(t.auto_accept);
        assert_eq!(t.instrument.as_deref(), Some("USDX"));
        assert_eq!(t.from.as_deref(), Some("Alice"));
        assert_eq!(t.to.as_deref(), Some("Bob"));
        assert_eq!(t.amount.as_deref(), Some("30.0"));

        let sub = Wrapper::try_parse_from([
            "token",
            "transfer",
            "--name",
            "inst1",
            "accept",
            "00instrcid",
            "--actor",
            "Bob",
        ])
        .expect("parse transfer accept");
        let TokenCommand::Transfer(t2) = sub.token.command else {
            panic!("expected Transfer");
        };
        assert!(matches!(t2.action, Some(TransferAction::Accept(_))));

        let alloc = Wrapper::try_parse_from([
            "token",
            "allocation",
            "create",
            "--name",
            "inst1",
            "--settlement-id",
            "dvp-1",
            "--executor",
            "Admin",
            "--authorizer",
            "Alice",
            "--leg",
            "leg1:sender:Bob:USDX:10.0",
        ])
        .expect("parse allocation create");
        let TokenCommand::Allocation(a) = alloc.token.command else {
            panic!("expected Allocation");
        };
        assert!(matches!(a.command, AllocationCommand::Create(_)));
    }
}
