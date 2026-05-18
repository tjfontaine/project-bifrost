# host/bifrost Refactoring Plan

The `lower.rs` file has grown to ~2.1K lines and handles too many responsibilities. We should split it into several smaller modules to improve maintainability and testability.

## Proposed Module Structure

- `lower/mod.rs`: Main entry point and orchestration.
- `lower/state.rs`: `LowerState` struct and its implementation.
- `lower/emit.rs`: eBPF instruction emission helpers (`bpf_mov64_imm`, etc.).
- `lower/prologue.rs`: Boilerplate emission for kprobes/profile probes.
- `lower/action.rs`: Handlers for DTrace actions (`printf`, `stack`, `agg`).
- `lower/dif.rs`: Logic for lowering individual DIF instructions.
- `lower/branch.rs`: Branch fixup and placeholder logic.

## Symbolic Label System

To replace the manual `insn_offsets` and byte-patching branch logic, we should introduce a `Label` system:

```rust
enum Instruction {
    Insn([u8; 8]),
    Label(LabelId),
    Branch(Op, LabelId),
}
```

The assembler will then perform two passes:
1. Resolve `Label` positions.
2. Resolve `Branch` offsets based on labels.
3. Emit final bytes.

This will make the lowering logic much more robust and less prone to off-by-one errors.
