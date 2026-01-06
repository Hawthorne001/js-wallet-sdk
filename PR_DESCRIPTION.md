# Package Dependencies Upgrade - 2026.1.5 Release

## Summary

This pull request introduces comprehensive package version upgrades across all coin-specific modules in the js-wallet-sdk monorepo. The changes include dependency updates, test suite refactoring, and code improvements to ensure compatibility with the latest package versions.

**Statistics**: 261 files changed, 79,755 insertions(+), 51,954 deletions(-)

## Package Version Upgrades

### Core Packages
- **@okxweb3/coin-base**: `2.0.3` → `2.0.6`
- **@okxweb3/coin-ethereum**: `2.4.0` → `2.4.8`
- **@okxweb3/coin-bitcoin**: `2.4.0` → `2.4.9`

### Layer 1 Blockchains
- **@okxweb3/coin-aptos**: `2.4.0` → `2.4.8`
- **@okxweb3/coin-solana**: `2.4.2` → `2.4.8`
- **@okxweb3/coin-cardano**: `2.4.0` → `2.4.9`
- **@okxweb3/coin-cosmos**: `2.4.0` → `2.4.9`
- **@okxweb3/coin-near**: `2.4.0` → `2.4.9`
- **@okxweb3/coin-sui**: `2.4.0` → `2.4.8`
- **@okxweb3/coin-stacks**: `2.4.0` → `2.4.9`
- **@okxweb3/coin-starknet**: `2.4.0` → `2.4.9`
- **@okxweb3/coin-kaspa**: `2.4.0` → `2.4.9`
- **@okxweb3/coin-nostrassets**: `2.4.0` → `2.4.8`

### Other Chains
- **@okxweb3/coin-tron**: `2.4.0` → `2.4.9`
- **@okxweb3/coin-xrp**: `2.4.0` → `2.4.9`
- **@okxweb3/coin-stellar**: `2.4.0` → `2.4.8`
- **@okxweb3/coin-ton**: `2.4.0` → `2.4.8`
- **@okxweb3/coin-eos**: `2.4.0` → `2.4.8`
- **@okxweb3/coin-kaia**: `2.4.0` → `2.4.8`
- **@okxweb3/coin-zkspace**: `2.4.0` → `2.4.8`

## Key Changes

- Updated package versions across 20 coin modules
- Refactored test suites to align with updated dependencies
- Updated internal implementations and type definitions
- Synchronized dependency versions for consistency

## Testing

All test suites have been updated and verified for compatibility with new package versions.

## Breaking Changes

None. This is a maintenance release maintaining backward compatibility.

## Checklist

- [x] All package dependencies updated
- [x] Test suites updated and passing
- [x] CHANGELOG.md files updated where applicable
- [x] No breaking changes introduced

---

**Branch**: `2026.1.5` | **Base**: `main` | **Commits**: 12

