use crate::{
    gas::{self, warm_cold_cost, warm_cold_cost_with_delegation},
    interpreter::Interpreter,
    primitives::{Bytes, Log, LogData, Spec, SpecId::*, B256, U256},
    Host, InstructionResult,
};
use core::cmp::min;
use std::vec::Vec;
#[cfg(feature = "telos")]
use revm_primitives::keccak256;

pub fn balance<H: Host + ?Sized, SPEC: Spec>(interpreter: &mut Interpreter, host: &mut H) {
    pop_address!(interpreter, address);
    let Some(balance) = host.balance(address) else {
        interpreter.instruction_result = InstructionResult::FatalExternalError;
        return;
    };
    gas!(
        interpreter,
        if SPEC::enabled(BERLIN) {
            warm_cold_cost(balance.is_cold)
        } else if SPEC::enabled(ISTANBUL) {
            // EIP-1884: Repricing for trie-size-dependent opcodes
            700
        } else if SPEC::enabled(TANGERINE) {
            400
        } else {
            20
        }
    );
    #[cfg(feature = "telos")]
    let is_new_address = host.load_account_delegated(address).unwrap().is_empty;
    #[cfg(feature = "telos")]
    if host.env_mut().tx.first_new_address.is_none() && is_new_address{
        host.env_mut().tx.first_new_address = Some(address)
    }
    #[cfg(not(feature = "telos"))]
    push!(interpreter, balance.data);
    #[cfg(feature = "telos")]
    push!(interpreter, if host.env().tx.revision_number == 0 && is_new_address {
        U256::ZERO
    } else {
        balance.data
    });
}

/// EIP-1884: Repricing for trie-size-dependent opcodes
pub fn selfbalance<H: Host + ?Sized, SPEC: Spec>(interpreter: &mut Interpreter, host: &mut H) {
    check!(interpreter, ISTANBUL);
    gas!(interpreter, gas::LOW);
    let Some(balance) = host.balance(interpreter.contract.target_address) else {
        interpreter.instruction_result = InstructionResult::FatalExternalError;
        return;
    };
    push!(interpreter, balance.data);
}

pub fn extcodesize<H: Host + ?Sized, SPEC: Spec>(interpreter: &mut Interpreter, host: &mut H) {
    pop_address!(interpreter, address);
    let Some(code) = host.code(address) else {
        interpreter.instruction_result = InstructionResult::FatalExternalError;
        return;
    };
    let (code, load) = code.into_components();
    if SPEC::enabled(BERLIN) {
        gas!(interpreter, warm_cold_cost_with_delegation(load));
    } else if SPEC::enabled(TANGERINE) {
        gas!(interpreter, 700);
    } else {
        gas!(interpreter, 20);
    }

    #[cfg(feature = "telos")]
    let is_new_address = host.load_account_delegated(address).unwrap().is_empty;
    #[cfg(feature = "telos")]
    if host.env_mut().tx.first_new_address.is_none() && is_new_address {
        host.env_mut().tx.first_new_address = Some(address)
    }
    #[cfg(not(feature = "telos"))]
    push!(interpreter, U256::from(code.len()));
    #[cfg(feature = "telos")]
    push!(interpreter, if host.env().tx.revision_number == 0 && is_new_address {
        U256::from(0)
    } else {
        U256::from(code.len())
    });
}

/// EIP-1052: EXTCODEHASH opcode
pub fn extcodehash<H: Host + ?Sized, SPEC: Spec>(interpreter: &mut Interpreter, host: &mut H) {
    check!(interpreter, CONSTANTINOPLE);
    pop_address!(interpreter, address);
    let Some(code_hash) = host.code_hash(address) else {
        interpreter.instruction_result = InstructionResult::FatalExternalError;
        return;
    };
    let (code_hash, load) = code_hash.into_components();
    if SPEC::enabled(BERLIN) {
        gas!(interpreter, warm_cold_cost_with_delegation(load))
    } else if SPEC::enabled(ISTANBUL) {
        gas!(interpreter, 700);
    } else {
        gas!(interpreter, 400);
    }
    #[cfg(feature = "telos")]
    let is_new_address = host.load_account_delegated(address).unwrap().is_empty;
    #[cfg(feature = "telos")]
    if host.env_mut().tx.first_new_address.is_none() && is_new_address{
        host.env_mut().tx.first_new_address = Some(address)
    }
    #[cfg(not(feature = "telos"))]
    push_b256!(interpreter, code_hash);
    #[cfg(feature = "telos")]
    push_b256!(interpreter, if host.env().tx.revision_number == 0 && is_new_address {
        U256::ZERO.into()
    } else {
        code_hash
    });
}

pub fn extcodecopy<H: Host + ?Sized, SPEC: Spec>(interpreter: &mut Interpreter, host: &mut H) {
    pop_address!(interpreter, address);
    pop!(interpreter, memory_offset, code_offset, len_u256);

    let Some(code) = host.code(address) else {
        interpreter.instruction_result = InstructionResult::FatalExternalError;
        return;
    };

    let len = as_usize_or_fail!(interpreter, len_u256);
    let (code, load) = code.into_components();
    gas_or_fail!(
        interpreter,
        gas::extcodecopy_cost(SPEC::SPEC_ID, len as u64, load)
    );
    if len == 0 {
        return;
    }
    let memory_offset = as_usize_or_fail!(interpreter, memory_offset);
    let code_offset = min(as_usize_saturated!(code_offset), code.len());
    resize_memory!(interpreter, memory_offset, len);

    // Note: this can't panic because we resized memory to fit.
    #[cfg(feature = "telos")]
    let is_new_address = host.load_account_delegated(address).unwrap().is_empty;
    #[cfg(feature = "telos")]
    if host.env_mut().tx.first_new_address.is_none() && is_new_address{
        host.env_mut().tx.first_new_address = Some(address)
    }
    #[cfg(feature = "telos")]
    let empty_code = Bytes::default();
    #[cfg(not(feature = "telos"))]
    interpreter
        .shared_memory
        .set_data(memory_offset, code_offset, len, &code);
    #[cfg(feature = "telos")]
    interpreter
        .shared_memory
        .set_data(memory_offset, code_offset, len, if host.env().tx.revision_number == 0 && is_new_address {
            &empty_code
        } else {
            &code
        });
}

pub fn blockhash<H: Host + ?Sized, SPEC: Spec>(interpreter: &mut Interpreter, host: &mut H) {
    gas!(interpreter, gas::BLOCKHASH);
    pop_top!(interpreter, number);

    let number_u64 = as_u64_saturated!(number);
    #[cfg(not(feature = "telos"))]
    let Some(hash) = host.block_hash(number_u64) else {
        interpreter.instruction_result = InstructionResult::FatalExternalError;
        return;
    };
    #[cfg(not(feature = "telos"))] {
        *number = U256::from_be_bytes(hash.0);
    }
    #[cfg(feature = "telos")]
    if *number == host.env().block.number || (host.env().block.number - *number) > U256::from(256) {
        *number = U256::ZERO;
    } else {
        let number_string = number_u64.to_string();
        let hash = keccak256(number_string);
        *number = U256::from_be_bytes(hash.0);
    }
}

pub fn sload<H: Host + ?Sized, SPEC: Spec>(interpreter: &mut Interpreter, host: &mut H) {
    pop_top!(interpreter, index);
    let Some(value) = host.sload(interpreter.contract.target_address, *index) else {
        interpreter.instruction_result = InstructionResult::FatalExternalError;
        return;
    };
    gas!(interpreter, gas::sload_cost(SPEC::SPEC_ID, value.is_cold));
    *index = value.data;
}

pub fn sstore<H: Host + ?Sized, SPEC: Spec>(interpreter: &mut Interpreter, host: &mut H) {
    require_non_staticcall!(interpreter);

    pop!(interpreter, index, value);
    let Some(state_load) = host.sstore(interpreter.contract.target_address, index, value) else {
        interpreter.instruction_result = InstructionResult::FatalExternalError;
        return;
    };
    gas_or_fail!(interpreter, {
        let remaining_gas = interpreter.gas.remaining();
        gas::sstore_cost(
            SPEC::SPEC_ID,
            &state_load.data,
            remaining_gas,
            state_load.is_cold,
        )
    });
    refund!(
        interpreter,
        gas::sstore_refund(SPEC::SPEC_ID, &state_load.data)
    );
}

/// EIP-1153: Transient storage opcodes
/// Store value to transient storage
pub fn tstore<H: Host + ?Sized, SPEC: Spec>(interpreter: &mut Interpreter, host: &mut H) {
    check!(interpreter, CANCUN);
    require_non_staticcall!(interpreter);
    gas!(interpreter, gas::WARM_STORAGE_READ_COST);

    pop!(interpreter, index, value);

    host.tstore(interpreter.contract.target_address, index, value);
}

/// EIP-1153: Transient storage opcodes
/// Load value from transient storage
pub fn tload<H: Host + ?Sized, SPEC: Spec>(interpreter: &mut Interpreter, host: &mut H) {
    check!(interpreter, CANCUN);
    gas!(interpreter, gas::WARM_STORAGE_READ_COST);

    pop_top!(interpreter, index);

    *index = host.tload(interpreter.contract.target_address, *index);
}

pub fn log<const N: usize, H: Host + ?Sized>(interpreter: &mut Interpreter, host: &mut H) {
    require_non_staticcall!(interpreter);

    pop!(interpreter, offset, len);
    let len = as_usize_or_fail!(interpreter, len);
    gas_or_fail!(interpreter, gas::log_cost(N as u8, len as u64));
    let data = if len == 0 {
        Bytes::new()
    } else {
        let offset = as_usize_or_fail!(interpreter, offset);
        resize_memory!(interpreter, offset, len);
        Bytes::copy_from_slice(interpreter.shared_memory.slice(offset, len))
    };

    if interpreter.stack.len() < N {
        interpreter.instruction_result = InstructionResult::StackUnderflow;
        return;
    }

    let mut topics = Vec::with_capacity(N);
    for _ in 0..N {
        // SAFETY: stack bounds already checked few lines above
        topics.push(B256::from(unsafe { interpreter.stack.pop_unsafe() }));
    }

    let log = Log {
        address: interpreter.contract.target_address,
        data: LogData::new(topics, data).expect("LogData should have <=4 topics"),
    };

    host.log(log);
}

pub fn selfdestruct<H: Host + ?Sized, SPEC: Spec>(interpreter: &mut Interpreter, host: &mut H) {
    require_non_staticcall!(interpreter);
    pop_address!(interpreter, target);

    let Some(res) = host.selfdestruct(interpreter.contract.target_address, target) else {
        interpreter.instruction_result = InstructionResult::FatalExternalError;
        return;
    };

    // EIP-3529: Reduction in refunds
    if !SPEC::enabled(LONDON) && !res.previously_destroyed {
        refund!(interpreter, gas::SELFDESTRUCT)
    }
    gas!(interpreter, gas::selfdestruct_cost(SPEC::SPEC_ID, res));
    #[cfg(feature = "telos")]
    let is_new_address = host.load_account_delegated(target).unwrap().is_empty;
    #[cfg(feature = "telos")]
    if host.env_mut().tx.first_new_address.is_none() && is_new_address{
        host.env_mut().tx.first_new_address = Some(target)
    }

    interpreter.instruction_result = InstructionResult::SelfDestruct;
}
