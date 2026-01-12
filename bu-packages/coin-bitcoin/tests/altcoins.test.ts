import {
    BchWallet,
    BsvWallet,
    UsdtWallet,
    DogeWallet,
    LtcWallet,
    TBtcWallet,
    BtcWallet,
} from '../src/wallet';
import { InvalidPrivateKeyError } from '@okxweb3/coin-base';
import { message } from '../src';

describe('Bitcoin Alternative Coin Wallets', () => {
    const validPrivateKey =
        'KwTqEP5swztao5UdMWpxaAGtvmvQFjYGe1UDyrsZxjkLX9KVpN36';
    const testnetPrivateKey =
        'cNtoPYke9Dhqoa463AujyLzeas8pa6S15BG1xDSRnVmcwbS9w7rS';

    describe('BchWallet address validation', () => {
        let bchWallet: BchWallet;

        beforeEach(() => {
            bchWallet = new BchWallet();
        });

        test('should accept valid Bitcoin Cash addresses', async () => {
            const validAddresses = [
                {
                    address:
                        'bitcoincash:qqp6jzlt589ev7enlxc9yx8ptv5q0l6cqgrhjedvqm',
                    type: 'Cash address',
                },
                {
                    address: '1GhLyRg4zzFixW3ZY5ViFzT4W5zTT9h7Pc',
                    type: 'Legacy',
                },
                {
                    address: '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy',
                    type: 'Script Hash',
                },
            ];

            for (const { address, type } of validAddresses) {
                const txData = {
                    inputs: [
                        {
                            txId: 'a7881146cc7671ad89dcd1d99015ed7c5e17cfae69eedd01f73f5ab60a6c1318',
                            vOut: 0,
                            amount: 100000,
                        },
                    ],
                    outputs: [
                        {
                            address: address,
                            amount: 50000,
                        },
                    ],
                    address: '1GhLyRg4zzFixW3ZY5ViFzT4W5zTT9h7Pc', // Valid change address
                    feePerB: 2,
                };

                const result = await bchWallet.signTransaction({
                    privateKey: validPrivateKey,
                    data: txData,
                });
                expect(result).toBeDefined();
            }
        });

        test('should reject invalid recipient addresses', async () => {
            const invalidAddresses = [
                { address: '', reason: 'Empty string' },
                { address: 'invalid', reason: 'Invalid format' },
                {
                    address: '0x742d35Cc6634C0532925a3b8D65428C6c2b8b5d5',
                    reason: 'Ethereum address',
                },
                {
                    address: 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
                    reason: 'Bitcoin SegWit address (BCH does not support segwit)',
                },
                {
                    address:
                        'bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297',
                    reason: 'Bitcoin Taproot address (BCH does not support segwit)',
                },
                { address: 'alice', reason: 'EOS account name' },
                { address: null, reason: 'Null value' },
                { address: undefined, reason: 'Undefined value' },
            ];

            for (const { address, reason } of invalidAddresses) {
                const txData = {
                    inputs: [{ txId: 'a'.repeat(64), vOut: 0, amount: 100000 }],
                    outputs: [{ address: address as any, amount: 50000 }],
                    address: '1GhLyRg4zzFixW3ZY5ViFzT4W5zTT9h7Pc',
                    feePerB: 2,
                };

                await expect(
                    bchWallet.signTransaction({
                        privateKey: validPrivateKey,
                        data: txData,
                    })
                ).rejects.toMatch(/sign tx error/);
            }
        });

        test('should reject invalid change addresses', async () => {
            const invalidChangeAddresses = [
                { address: '', reason: 'Empty string' },
                { address: 'invalid', reason: 'Invalid format' },
                {
                    address: '0x742d35Cc6634C0532925a3b8D65428C6c2b8b5d5',
                    reason: 'Ethereum address',
                },
                { address: null, reason: 'Null value' },
            ];

            for (const { address, reason } of invalidChangeAddresses) {
                const txData = {
                    inputs: [{ txId: 'a'.repeat(64), vOut: 0, amount: 100000 }],
                    outputs: [
                        {
                            address: '1GhLyRg4zzFixW3ZY5ViFzT4W5zTT9h7Pc',
                            amount: 50000,
                        },
                    ],
                    address: address as any, // Invalid change address
                    feePerB: 2,
                };

                await expect(
                    bchWallet.signTransaction({
                        privateKey: validPrivateKey,
                        data: txData,
                    })
                ).rejects.toMatch(/sign tx error/);
            }
        });
    });

    describe('BsvWallet address validation', () => {
        let bsvWallet: BsvWallet;

        beforeEach(() => {
            bsvWallet = new BsvWallet();
        });

        test('should accept valid BSV addresses', async () => {
            const validAddresses = [
                {
                    address: '1GhLyRg4zzFixW3ZY5ViFzT4W5zTT9h7Pc',
                    type: 'Legacy',
                },
                {
                    address: '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy',
                    type: 'Script Hash',
                },
            ];

            for (const { address, type } of validAddresses) {
                const txData = {
                    inputs: [
                        {
                            txId: 'a7881146cc7671ad89dcd1d99015ed7c5e17cfae69eedd01f73f5ab60a6c1318',
                            vOut: 0,
                            amount: 100000,
                        },
                    ],
                    outputs: [
                        {
                            address: address,
                            amount: 50000,
                        },
                    ],
                    address: '1GhLyRg4zzFixW3ZY5ViFzT4W5zTT9h7Pc',
                    feePerB: 2,
                };

                const result = await bsvWallet.signTransaction({
                    privateKey: validPrivateKey,
                    data: txData,
                });
                expect(result).toBeDefined();
            }
        });

        test('should reject invalid recipient addresses', async () => {
            const invalidAddresses = [
                { address: '', reason: 'Empty string' },
                { address: 'invalid', reason: 'Invalid format' },
                {
                    address: '0x742d35Cc6634C0532925a3b8D65428C6c2b8b5d5',
                    reason: 'Ethereum address',
                },
                {
                    address: 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
                    reason: 'Bitcoin SegWit address (BSV does not support segwit)',
                },
                {
                    address:
                        'bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297',
                    reason: 'Bitcoin Taproot address (BSV does not support segwit)',
                },
                { address: null, reason: 'Null value' },
                { address: undefined, reason: 'Undefined value' },
            ];

            for (const { address, reason } of invalidAddresses) {
                const txData = {
                    inputs: [{ txId: 'a'.repeat(64), vOut: 0, amount: 100000 }],
                    outputs: [{ address: address as any, amount: 50000 }],
                    address: '1GhLyRg4zzFixW3ZY5ViFzT4W5zTT9h7Pc',
                    feePerB: 2,
                };

                await expect(
                    bsvWallet.signTransaction({
                        privateKey: validPrivateKey,
                        data: txData,
                    })
                ).rejects.toMatch(/sign tx error/);
            }
        });

        test('should reject invalid change addresses', async () => {
            const invalidChangeAddresses = [
                { address: '', reason: 'Empty string' },
                { address: 'invalid', reason: 'Invalid format' },
                {
                    address: '0x742d35Cc6634C0532925a3b8D65428C6c2b8b5d5',
                    reason: 'Ethereum address',
                },
                { address: null, reason: 'Null value' },
                { address: undefined, reason: 'Undefined value' },
            ];

            for (const { address, reason } of invalidChangeAddresses) {
                const txData = {
                    inputs: [{ txId: 'a'.repeat(64), vOut: 0, amount: 100000 }],
                    outputs: [
                        {
                            address: '1GhLyRg4zzFixW3ZY5ViFzT4W5zTT9h7Pc',
                            amount: 50000,
                        },
                    ],
                    address: address as any, // Invalid change address
                    feePerB: 2,
                };

                await expect(
                    bsvWallet.signTransaction({
                        privateKey: validPrivateKey,
                        data: txData,
                    })
                ).rejects.toMatch(/sign tx error/);
            }
        });
    });

    describe('UsdtWallet address validation', () => {
        let usdtWallet: UsdtWallet;

        beforeEach(() => {
            usdtWallet = new UsdtWallet();
        });

        test('should accept valid USDT transaction addresses', async () => {
            const validAddresses = [
                {
                    address: '1GhLyRg4zzFixW3ZY5ViFzT4W5zTT9h7Pc',
                    type: 'Legacy',
                },
                {
                    address: 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
                    type: 'Native SegWit',
                },
                {
                    address: '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy',
                    type: 'SegWit P2SH',
                },
                {
                    address:
                        'bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297',
                    type: 'Taproot',
                },
            ];

            for (const { address, type } of validAddresses) {
                const txData = {
                    inputs: [
                        {
                            txId: 'a7881146cc7671ad89dcd1d99015ed7c5e17cfae69eedd01f73f5ab60a6c1318',
                            vOut: 0,
                            amount: 100000,
                        },
                    ],
                    outputs: [
                        {
                            address: address,
                            amount: 50000,
                        },
                    ],
                    address: '1GhLyRg4zzFixW3ZY5ViFzT4W5zTT9h7Pc',
                    feePerB: 2,
                    omni: {
                        coinType: 31, // USDT
                        amount: 1000000, // 10 USDT
                    },
                };

                const result = await usdtWallet.signTransaction({
                    privateKey: validPrivateKey,
                    data: txData,
                });
                expect(result).toBeDefined();
            }
        });

        test('should reject invalid recipient addresses', async () => {
            const invalidAddresses = [
                { address: '', reason: 'Empty string' },
                { address: 'invalid', reason: 'Invalid format' },
                {
                    address: '0x742d35Cc6634C0532925a3b8D65428C6c2b8b5d5',
                    reason: 'Ethereum address',
                },
                { address: null, reason: 'Null value' },
                { address: undefined, reason: 'Undefined value' },
            ];

            for (const { address, reason } of invalidAddresses) {
                const txData = {
                    inputs: [{ txId: 'a'.repeat(64), vOut: 0, amount: 100000 }],
                    outputs: [{ address: address as any, amount: 50000 }],
                    address: '1GhLyRg4zzFixW3ZY5ViFzT4W5zTT9h7Pc',
                    feePerB: 2,
                    omni: { coinType: 31, amount: 1000000 },
                };

                await expect(
                    usdtWallet.signTransaction({
                        privateKey: validPrivateKey,
                        data: txData,
                    })
                ).rejects.toMatch(/sign tx error/);
            }
        });

        test('should reject transaction without omni data', async () => {
            const txData = {
                inputs: [{ txId: 'a'.repeat(64), vOut: 0, amount: 100000 }],
                outputs: [
                    {
                        address: '1GhLyRg4zzFixW3ZY5ViFzT4W5zTT9h7Pc',
                        amount: 50000,
                    },
                ],
                address: '1GhLyRg4zzFixW3ZY5ViFzT4W5zTT9h7Pc',
                feePerB: 2,
                // Missing omni field
            };

            await expect(
                usdtWallet.signTransaction({
                    privateKey: validPrivateKey,
                    data: txData,
                })
            ).rejects.toMatch(/sign tx error/);
        });

        test('should reject invalid change addresses', async () => {
            const invalidChangeAddresses = [
                { address: '', reason: 'Empty string' },
                { address: 'invalid', reason: 'Invalid format' },
                {
                    address: '0x742d35Cc6634C0532925a3b8D65428C6c2b8b5d5',
                    reason: 'Ethereum address',
                },
                { address: null, reason: 'Null value' },
                { address: undefined, reason: 'Undefined value' },
            ];

            for (const { address, reason } of invalidChangeAddresses) {
                const txData = {
                    inputs: [{ txId: 'a'.repeat(64), vOut: 0, amount: 100000 }],
                    outputs: [
                        {
                            address: '1GhLyRg4zzFixW3ZY5ViFzT4W5zTT9h7Pc',
                            amount: 50000,
                        },
                    ],
                    address: address as any, // Invalid change address
                    feePerB: 2,
                    omni: { coinType: 31, amount: 1000000 },
                };

                await expect(
                    usdtWallet.signTransaction({
                        privateKey: validPrivateKey,
                        data: txData,
                    })
                ).rejects.toMatch(/sign tx error/);
            }
        });
    });

    describe('DogeWallet and LtcWallet inheritance', () => {
        test('DogeWallet should inherit BtcWallet validation for regular transactions', async () => {
            const dogeWallet = new DogeWallet();

            const txData = {
                inputs: [{ txId: 'a'.repeat(64), vOut: 0, amount: 100000 }],
                outputs: [{ address: 'invalid_address', amount: 50000 }],
                address: 'DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L', // Valid Doge address
                feePerB: 2,
            };

            // Should fail due to invalid recipient address (inherits BtcWallet validation)
            await expect(
                dogeWallet.signTransaction({
                    privateKey: validPrivateKey,
                    data: txData,
                })
            ).rejects.toMatch(/sign tx error/);
        });

        test('LtcWallet should inherit BtcWallet validation automatically', async () => {
            const ltcWallet = new LtcWallet();

            const txData = {
                inputs: [{ txId: 'a'.repeat(64), vOut: 0, amount: 100000 }],
                outputs: [{ address: 'invalid_address', amount: 50000 }],
                address: 'LdP8Qox1VAhCzLJNqrr74YovaWYyNBUWvL', // Valid LTC address
                feePerB: 2,
            };

            // Should fail due to invalid recipient address (inherits BtcWallet validation)
            await expect(
                ltcWallet.signTransaction({
                    privateKey: validPrivateKey,
                    data: txData,
                })
            ).rejects.toMatch(/sign tx error/);
        });
    });

    describe('LtcWallet signMessage edge cases', () => {
        test('signMessage should reject when privateKey is empty', async () => {
            const ltcWallet = new LtcWallet();

            await expect(
                ltcWallet.signMessage({
                    privateKey: '',
                    data: {
                        type: 0,
                        message: 'hello world!',
                    },
                })
            ).rejects.toMatch(`${InvalidPrivateKeyError}: cannot be empty`);
        });

        test('getMPCRawMessage should return hash without privateKey', async () => {
            const ltcWallet = new LtcWallet();
            const messageText = 'Hello MPC';

            const result = await ltcWallet.getMPCRawMessage({
                data: {
                    type: 0,
                    message: messageText,
                },
            } as any);

            expect(result).toEqual({
                hash: '10b1d83b080e62d7b8ef418388cb126f094c86e705f8493c7ef1b246b91cb4ee',
            });
        });
    });

    describe('Network-specific validation', () => {
        test('Mainnet wallets should reject testnet addresses', async () => {
            const mainnetWallet = new BtcWallet();

            const txData = {
                inputs: [{ txId: 'a'.repeat(64), vOut: 0, amount: 100000 }],
                outputs: [
                    {
                        address: 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx',
                        amount: 50000,
                    },
                ], // Testnet address
                address: '1GhLyRg4zzFixW3ZY5ViFzT4W5zTT9h7Pc',
                feePerB: 2,
            };

            await expect(
                mainnetWallet.signTransaction({
                    privateKey: validPrivateKey,
                    data: txData,
                })
            ).rejects.toMatch(/sign tx error/);
        });

        test('Testnet wallets should reject mainnet addresses', async () => {
            const testnetWallet = new TBtcWallet();

            const txData = {
                inputs: [{ txId: 'a'.repeat(64), vOut: 0, amount: 100000 }],
                outputs: [
                    {
                        address: 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
                        amount: 50000,
                    },
                ], // Mainnet address
                address: 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx',
                feePerB: 2,
            };

            await expect(
                testnetWallet.signTransaction({
                    privateKey: testnetPrivateKey,
                    data: txData,
                })
            ).rejects.toMatch(/sign tx error/);
        });
    });
});
