import { KaspaWallet } from '../src';
import { InvalidPrivateKeyError } from '@okxweb3/coin-base';
const wallet = new KaspaWallet();

describe('kaspa', () => {
    test('null privateKey should error', async () => {
        const wallet = new KaspaWallet();
        const signParams: any = {
            // @ts-ignore
            privateKey: null,
            data: {},
        };
        await expect(wallet.signTransaction(signParams)).rejects.toEqual(
            InvalidPrivateKeyError
        );
    });
    test('signCommonMsg', async () => {
        let wallet = new KaspaWallet();
        let sig = await wallet.signCommonMsg({
            privateKey:
                'd636a23d4f49fe4e0d59fcf7a6c2ab3846ff2d3a54007b3817a11dff770d06ff',
            message: { walletId: '123456789' },
        });
        expect(sig).toEqual(
            '1ca64e53306b181d26888429d9cdaa22cebd4b4fd84f5d0aaa0699df7d996299587fea8ba53890ebe09f55a9ac4ae867059b496bd8feabb97f8a4e20a34b73bc21'
        );
        sig = await wallet.signCommonMsg({
            privateKey:
                'd636a23d4f49fe4e0d59fcf7a6c2ab3846ff2d3a54007b3817a11dff770d06ff',
            message: { text: '123456789' },
        });
        expect(sig).toEqual(
            '1c96f99670d2685250aed3a633e5e37d15b0ee26e6e360fc35df7b00ea117e5e706f93a16291fedb829f9307dd03678f0d2178bf4011ed19fa4200f94f6b294270'
        );
    });

    test('derive privateKey', async () => {
        const privateKey = await wallet.getDerivedPrivateKey({
            mnemonic:
                'reopen vivid parent want raw main filter rotate earth true fossil dream',
            hdPath: "m/44'/111111'/0'/0/0",
        });
        expect(privateKey).toBe(
            '0xd636a23d4f49fe4e0d59fcf7a6c2ab3846ff2d3a54007b3817a11dff770d06ff'
        );
    });

    const ps: any[] = [];
    ps.push('');
    ps.push('0x');
    ps.push('124699');
    ps.push('1dfi付');
    ps.push('9000 12');
    ps.push(
        '548yT115QRHH7Mpchg9JJ8YPX9RTKuan=548yT115QRHH7Mpchg9JJ8YPX9RTKuan '
    );
    ps.push(
        'L1vSc9DuBDeVkbiS79mJ441FNAYArL1vSc9DuBDeVkbiS79mJ441FNAYArL1vSc9DuBDeVkbiS79mJ441FNAYArL1vSc9DuBDeVkbiS79mJ441FNAYAr'
    );
    ps.push('L1v');
    ps.push(
        '0x31342f041c5b54358074b4579231c8a300be65e687dff020bc7779598b428 97a'
    );
    ps.push(
        '0x31342f041c5b54358074b457。、。9231c8a300be65e687dff020bc7779598b428 97a'
    );
    ps.push('0000000000000000000000000000000000000000000000000000000000000000');
    test('edge test', async () => {
        const wallet = new KaspaWallet();
        let j = 1;
        for (let i = 0; i < ps.length; i++) {
            try {
                await wallet.getNewAddress({ privateKey: ps[i] });
            } catch (e) {
                j = j + 1;
                expect(
                    (await wallet.validPrivateKey({ privateKey: ps[i] }))
                        .isValid
                ).toEqual(false);
            }
        }
        expect(j).toEqual(ps.length + 1);
    });
    test('validPrivateKey', async () => {
        const wallet = new KaspaWallet();
        const privateKeyTemp = await wallet.getRandomPrivateKey();
        const privateKey = privateKeyTemp.slice(2);
        expect(
            (await wallet.validPrivateKey({ privateKey: privateKey })).isValid
        ).toEqual(true);
        expect(
            (await wallet.validPrivateKey({ privateKey: '0x' + privateKey }))
                .isValid
        ).toEqual(true);
        expect(
            (await wallet.validPrivateKey({ privateKey: '0X' + privateKey }))
                .isValid
        ).toEqual(true);
        expect(
            (
                await wallet.validPrivateKey({
                    privateKey: '0X' + privateKey.toUpperCase(),
                })
            ).isValid
        ).toEqual(true);
    });

    test('getNewAddress', async () => {
        let address = await wallet.getNewAddress({
            privateKey:
                'd636a23d4f49fe4e0d59fcf7a6c2ab3846ff2d3a54007b3817a11dff770d06ff',
        });
        expect(address.address).toBe(
            'kaspa:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x'
        );
        expect(address.publicKey).toBe(
            '0395c7c9703e0ff81596043f0a5e00684f860a1ab0f24c5a94931d1e0d94c4be'
        );
        address = await wallet.getNewAddress({
            privateKey:
                '0xd636a23d4f49fe4e0d59fcf7a6c2ab3846ff2d3a54007b3817a11dff770d06ff',
        });
        expect(address.address).toBe(
            'kaspa:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x'
        );
        address = await wallet.getNewAddress({
            privateKey:
                'D636A23D4F49FE4E0D59FCF7A6C2AB3846FF2D3A54007B3817A11DFF770D06FF',
        });
        expect(address.address).toBe(
            'kaspa:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x'
        );
        address = await wallet.getNewAddress({
            privateKey:
                '0XD636A23D4F49FE4E0D59FCF7A6C2AB3846FF2D3A54007B3817A11DFF770D06FF',
        });
        expect(address.address).toBe(
            'kaspa:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x'
        );
    });

    test('validate address', async () => {
        expect(
            (
                await wallet.validAddress({
                    address:
                        'kaspa:qrcnkrtrjptghtrntvyqkqafj06f9tamn0pnqvelmt2vmz68yp4gqj5lnal2h',
                })
            ).isValid
        ).toBe(true);
        expect(
            (
                await wallet.validAddress({
                    address:
                        'kaspa:qrcnkrtrjptghtrntvyqkqafj06f9tamn0pnqvelmt2vmz68yp4gqj5lnal2a',
                })
            ).isValid
        ).toBe(false);
        expect(
            (
                await wallet.validAddress({
                    address:
                        'kaspa:prcnkrtrjptghtrntvyqkqafj06f9tamn0pnqvelmt2vmz68yp4gqj5lnal2h',
                })
            ).isValid
        ).toBe(false);
        expect(
            (
                await wallet.validAddress({
                    address:
                        'kaspa1:qrcnkrtrjptghtrntvyqkqafj06f9tamn0pnqvelmt2vmz68yp4gqj5lnal2h',
                })
            ).isValid
        ).toBe(false);
        expect(
            (
                await wallet.validAddress({
                    address:
                        'kaspa:1prcnkrtrjptghtrntvyqkqafj06f9tamn0pnqvelmt2vmz68yp4gqj5lnal2h',
                })
            ).isValid
        ).toBe(false);
        expect(
            (
                await wallet.validAddress({
                    address:
                        'kaspa:rcnkrtrjptghtrntvyqkqafj06f9tamn0pnqvelmt2vmz68yp4gqj5lnal2h',
                })
            ).isValid
        ).toBe(false);
    });

    test('transfer', async () => {
        const param = {
            data: {
                inputs: [
                    {
                        txId: 'ec62c785badb0ee693435841d35bd05da9c8a40aa2d568dddb0dd47410e7e78a',
                        vOut: 1,
                        address:
                            'kaspa:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x',
                        amount: 597700,
                    },
                ],
                outputs: [
                    {
                        address:
                            'kaspa:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x',
                        amount: 587700,
                    },
                ],
                address:
                    'kaspa:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x',
                fee: 10000,
            },
            privateKey:
                'd636a23d4f49fe4e0d59fcf7a6c2ab3846ff2d3a54007b3817a11dff770d06ff',
        };

        const tx = await wallet.signTransaction(param);
        console.log(tx);
    });

    test('calculate txId', async () => {
        const txId = await wallet.calcTxHash({
            data: {
                transaction: {
                    version: 0,
                    inputs: [
                        {
                            previousOutpoint: {
                                transactionId:
                                    'ec62c785badb0ee693435841d35bd05da9c8a40aa2d568dddb0dd47410e7e78a',
                                index: 1,
                            },
                            signatureScript:
                                '411687d956de8e3cc53b9dbf20ede3922b422595abbad31ecf38ff90c0cf8ef7c3b5ae71628e041a3a0f1b9ad6e14bb6d49dd7c35f06c46316b67c10d477c29ac001',
                            sequence: 0,
                            sigOpCount: 1,
                        },
                    ],
                    outputs: [
                        {
                            scriptPublicKey: {
                                version: 0,
                                scriptPublicKey:
                                    '200395c7c9703e0ff81596043f0a5e00684f860a1ab0f24c5a94931d1e0d94c4beac',
                            },
                            amount: 587700,
                        },
                    ],
                    lockTime: 0,
                    subnetworkId: '0000000000000000000000000000000000000000',
                },
                allowOrphan: false,
            },
        });

        expect(txId).toBe(
            'a1e32db317f2d843ad564d58e4348d24995a74ab3b6d205bf759747edeb127cf'
        );
    });

    test('sign message', async () => {
        const signature = await wallet.signMessage({
            data: {
                message: 'Hello Kaspa!',
            },
            privateKey:
                'd636a23d4f49fe4e0d59fcf7a6c2ab3846ff2d3a54007b3817a11dff770d06ff',
        });

        console.log(signature);
    });

    // Additional test cases to improve branch coverage
    describe('Error handling and edge cases', () => {
        test('signTransaction with invalid data should throw error', async () => {
            const invalidParam = {
                data: null, // Invalid data that will cause transfer function to fail
                privateKey:
                    'd636a23d4f49fe4e0d59fcf7a6c2ab3846ff2d3a54007b3817a11dff770d06ff',
            };

            await expect(wallet.signTransaction(invalidParam)).rejects.toBe(
                'sign tx error'
            );
        });

        test('signTransaction with invalid private key should throw error', async () => {
            const invalidParam = {
                data: {
                    inputs: [
                        {
                            txId: 'ec62c785badb0ee693435841d35bd05da9c8a40aa2d568dddb0dd47410e7e78a',
                            vOut: 1,
                            address:
                                'kaspa:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x',
                            amount: 597700,
                        },
                    ],
                    outputs: [
                        {
                            address:
                                'kaspa:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x',
                            amount: 587700,
                        },
                    ],
                    address:
                        'kaspa:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x',
                    fee: 10000,
                },
                privateKey: 'invalid_private_key', // Invalid private key
            };

            await expect(wallet.signTransaction(invalidParam)).rejects.toBe(
                'sign tx error'
            );
        });

        test('calcTxHash with string data should parse JSON', async () => {
            const stringData = JSON.stringify({
                transaction: {
                    version: 0,
                    inputs: [
                        {
                            previousOutpoint: {
                                transactionId:
                                    'ec62c785badb0ee693435841d35bd05da9c8a40aa2d568dddb0dd47410e7e78a',
                                index: 1,
                            },
                            signatureScript:
                                '411687d956de8e3cc53b9dbf20ede3922b422595abbad31ecf38ff90c0cf8ef7c3b5ae71628e041a3a0f1b9ad6e14bb6d49dd7c35f06c46316b67c10d477c29ac001',
                            sequence: 0,
                            sigOpCount: 1,
                        },
                    ],
                    outputs: [
                        {
                            scriptPublicKey: {
                                version: 0,
                                scriptPublicKey:
                                    '200395c7c9703e0ff81596043f0a5e00684f860a1ab0f24c5a94931d1e0d94c4beac',
                            },
                            amount: 587700,
                        },
                    ],
                    lockTime: 0,
                    subnetworkId: '0000000000000000000000000000000000000000',
                },
            });

            const txId = await wallet.calcTxHash({
                data: stringData,
            });

            expect(txId).toBe(
                'a1e32db317f2d843ad564d58e4348d24995a74ab3b6d205bf759747edeb127cf'
            );
        });

        test('calcTxHash with invalid JSON string should throw error', async () => {
            const invalidJsonString = 'invalid json string';

            await expect(
                wallet.calcTxHash({
                    data: invalidJsonString,
                })
            ).rejects.toBe('calculate tx hash error');
        });

        test('calcTxHash with invalid object data should throw error', async () => {
            const invalidData = {
                transaction: null, // Invalid transaction data
            };

            await expect(
                wallet.calcTxHash({
                    data: invalidData,
                })
            ).rejects.toBe('calculate tx hash error');
        });

        test('signMessage with invalid data should throw error', async () => {
            const invalidParam = {
                data: {
                    message: null, // Invalid message that will cause signMessage function to fail
                },
                privateKey:
                    'd636a23d4f49fe4e0d59fcf7a6c2ab3846ff2d3a54007b3817a11dff770d06ff',
            };

            await expect(wallet.signMessage(invalidParam)).rejects.toBe(
                'sign tx error'
            );
        });

        test('signMessage with invalid private key should throw error', async () => {
            const invalidParam = {
                data: {
                    message: 'Hello Kaspa!',
                },
                privateKey: 'invalid_private_key', // Invalid private key
            };

            await expect(wallet.signMessage(invalidParam)).rejects.toBe(
                `${InvalidPrivateKeyError}: not valid private key`
            );
        });

        test('signMessage with empty private key should throw error', async () => {
            const invalidParam = {
                data: {
                    message: 'Hello Kaspa!',
                },
                privateKey: '',
            };

            await expect(wallet.signMessage(invalidParam)).rejects.toBe(
                `${InvalidPrivateKeyError}: cannot be empty`
            );
        });
    });

    describe('getDerivedPath method', () => {
        test('getDerivedPath should return correct path format', async () => {
            const path = await wallet.getDerivedPath({ index: 0 });
            expect(path).toBe("m/44'/111111'/0'/0/0");

            const path2 = await wallet.getDerivedPath({ index: 5 });
            expect(path2).toBe("m/44'/111111'/0'/0/5");

            const path3 = await wallet.getDerivedPath({ index: 100 });
            expect(path3).toBe("m/44'/111111'/0'/0/100");
        });
    });

    describe('validPrivateKey edge cases', () => {
        test('validPrivateKey with various invalid formats', async () => {
            const wallet = new KaspaWallet();

            // Test with empty string
            expect(
                (await wallet.validPrivateKey({ privateKey: '' })).isValid
            ).toBe(false);

            // Test with non-hex string
            expect(
                (await wallet.validPrivateKey({ privateKey: 'not_hex_string' }))
                    .isValid
            ).toBe(false);

            // Test with too short hex string
            expect(
                (await wallet.validPrivateKey({ privateKey: '123456' })).isValid
            ).toBe(false);

            // Test with too long hex string
            expect(
                (
                    await wallet.validPrivateKey({
                        privateKey:
                            '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
                    })
                ).isValid
            ).toBe(false);

            // Test with all zeros (invalid private key)
            expect(
                (
                    await wallet.validPrivateKey({
                        privateKey:
                            '0000000000000000000000000000000000000000000000000000000000000000',
                    })
                ).isValid
            ).toBe(false);
        });
    });

    describe('validAddress edge cases', () => {
        test('validAddress with various invalid formats', async () => {
            const wallet = new KaspaWallet();

            // Test with empty string
            expect((await wallet.validAddress({ address: '' })).isValid).toBe(
                false
            );

            // Test with non-kaspa address
            expect(
                (
                    await wallet.validAddress({
                        address: '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
                    })
                ).isValid
            ).toBe(false);

            // Test with malformed kaspa address
            expect(
                (await wallet.validAddress({ address: 'kaspa:invalid' }))
                    .isValid
            ).toBe(false);

            // Test with wrong prefix
            expect(
                (
                    await wallet.validAddress({
                        address:
                            'bitcoin:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x',
                    })
                ).isValid
            ).toBe(false);
        });
    });

    // Comprehensive address validation tests
    test('validAddress - comprehensive validation testing', async () => {
        const wallet = new KaspaWallet();

        // Test valid Kaspa addresses (using known working addresses from existing tests)
        const validAddresses = [
            'kaspa:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x',
            'kaspa:qrcnkrtrjptghtrntvyqkqafj06f9tamn0pnqvelmt2vmz68yp4gqj5lnal2h',
        ];

        for (const address of validAddresses) {
            const result = await wallet.validAddress({ address });
            expect(result).toBeDefined();
            expect(result.isValid).toBe(true);
            expect(result.address).toBe(address);
        }

        // Test invalid Kaspa addresses
        const invalidAddresses = [
            // Wrong prefix
            'bitcoin:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x',
            'ethereum:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x',

            // Bitcoin addresses
            '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
            '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy',
            'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq',

            // Ethereum addresses
            '0x742d35Cc6634C0532925a3b844Bc454e4438f44e',
            '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',

            // Solana addresses
            '7NRmECq1R4tCtXNvmvDAuXmii3vN1J9DRZWhMCuuUnkM',
            'FZNZLT5diWHooSBjcng9qitykwcL9v3RiNrpC3fp9PU1',

            // NEAR addresses
            'alice.near',
            'contract.testnet',

            // Invalid formats
            '',
            'kaspa:',
            'kaspa:invalid',
            'invalid_address_format',
            'kaspa:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9', // too short
            'kaspa:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9xxx', // too long
        ];

        for (const address of invalidAddresses) {
            const result = await wallet.validAddress({ address });
            expect(result).toBeDefined();
            expect(result.isValid).toBe(false);
            expect(result.address).toBe(address);
        }
    });

    // Comprehensive signTransaction tests
    test('signTransaction - transfer with valid addresses', async () => {
        const wallet = new KaspaWallet();
        const privateKey =
            'd636a23d4f49fe4e0d59fcf7a6c2ab3846ff2d3a54007b3817a11dff770d06ff';

        const transferParams = {
            inputs: [
                {
                    txId: 'ec62c785badb0ee693435841d35bd05da9c8a40aa2d568dddb0dd47410e7e78a',
                    vOut: 1,
                    address:
                        'kaspa:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x', // Valid input address
                    amount: 597700,
                },
            ],
            outputs: [
                {
                    address:
                        'kaspa:qrcnkrtrjptghtrntvyqkqafj06f9tamn0pnqvelmt2vmz68yp4gqj5lnal2h', // Valid output address
                    amount: '587700',
                },
            ],
            address:
                'kaspa:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x', // Valid change address
            fee: '10000',
        };

        const result = await wallet.signTransaction({
            privateKey: privateKey,
            data: transferParams,
        });

        expect(result).toBeDefined();
        expect(typeof result).toBe('string');
    });

    test('signTransaction - transfer with invalid input address', async () => {
        const wallet = new KaspaWallet();
        const privateKey =
            'd636a23d4f49fe4e0d59fcf7a6c2ab3846ff2d3a54007b3817a11dff770d06ff';

        const transferParams = {
            inputs: [
                {
                    txId: 'ec62c785badb0ee693435841d35bd05da9c8a40aa2d568dddb0dd47410e7e78a',
                    vOut: 1,
                    address: '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', // Invalid input address (Bitcoin)
                    amount: 597700,
                },
            ],
            outputs: [
                {
                    address:
                        'kaspa:qrcnkrtrjptghtrntvyqkqafj06f9tamn0pnqvelmt2vmz68yp4gqj5lnal2h',
                    amount: '587700',
                },
            ],
            address:
                'kaspa:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x',
            fee: '10000',
        };

        try {
            await wallet.signTransaction({
                privateKey: privateKey,
                data: transferParams,
            });
            expect(true).toBe(false); // Should not reach here
        } catch (e) {
            expect(e).toBeDefined();
        }
    });

    test('signTransaction - transfer with invalid output address', async () => {
        const wallet = new KaspaWallet();
        const privateKey =
            'd636a23d4f49fe4e0d59fcf7a6c2ab3846ff2d3a54007b3817a11dff770d06ff';

        const transferParams = {
            inputs: [
                {
                    txId: 'ec62c785badb0ee693435841d35bd05da9c8a40aa2d568dddb0dd47410e7e78a',
                    vOut: 1,
                    address:
                        'kaspa:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x',
                    amount: 597700,
                },
            ],
            outputs: [
                {
                    address: '0x742d35Cc6634C0532925a3b844Bc454e4438f44e', // Invalid output address (Ethereum)
                    amount: '587700',
                },
            ],
            address:
                'kaspa:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x',
            fee: '10000',
        };

        try {
            await wallet.signTransaction({
                privateKey: privateKey,
                data: transferParams,
            });
            expect(true).toBe(false); // Should not reach here
        } catch (e) {
            expect(e).toBeDefined();
        }
    });

    test('signTransaction - transfer with invalid change address', async () => {
        const wallet = new KaspaWallet();
        const privateKey =
            'd636a23d4f49fe4e0d59fcf7a6c2ab3846ff2d3a54007b3817a11dff770d06ff';

        const transferParams = {
            inputs: [
                {
                    txId: 'ec62c785badb0ee693435841d35bd05da9c8a40aa2d568dddb0dd47410e7e78a',
                    vOut: 1,
                    address:
                        'kaspa:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x',
                    amount: 597700,
                },
            ],
            outputs: [
                {
                    address:
                        'kaspa:qrcnkrtrjptghtrntvyqkqafj06f9tamn0pnqvelmt2vmz68yp4gqj5lnal2h',
                    amount: '587700',
                },
            ],
            address: '7NRmECq1R4tCtXNvmvDAuXmii3vN1J9DRZWhMCuuUnkM', // Invalid change address (Solana)
            fee: '10000',
        };

        try {
            await wallet.signTransaction({
                privateKey: privateKey,
                data: transferParams,
            });
            expect(true).toBe(false); // Should not reach here
        } catch (e) {
            expect(e).toBeDefined();
        }
    });

    test('signTransaction - transfer with multiple valid addresses', async () => {
        const wallet = new KaspaWallet();
        const privateKey =
            'd636a23d4f49fe4e0d59fcf7a6c2ab3846ff2d3a54007b3817a11dff770d06ff';

        const validKaspaAddresses = [
            'kaspa:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x',
            'kaspa:qrcnkrtrjptghtrntvyqkqafj06f9tamn0pnqvelmt2vmz68yp4gqj5lnal2h',
        ];

        for (const address of validKaspaAddresses) {
            const transferParams = {
                inputs: [
                    {
                        txId: 'ec62c785badb0ee693435841d35bd05da9c8a40aa2d568dddb0dd47410e7e78a',
                        vOut: 1,
                        address: address, // Valid input address
                        amount: 597700,
                    },
                ],
                outputs: [
                    {
                        address: address, // Valid output address
                        amount: '587700',
                    },
                ],
                address: address, // Valid change address
                fee: '10000',
            };

            const result = await wallet.signTransaction({
                privateKey: privateKey,
                data: transferParams,
            });

            expect(result).toBeDefined();
            expect(typeof result).toBe('string');
        }
    });

    test('signTransaction - transfer with multiple inputs and outputs', async () => {
        const wallet = new KaspaWallet();
        const privateKey =
            'd636a23d4f49fe4e0d59fcf7a6c2ab3846ff2d3a54007b3817a11dff770d06ff';

        const transferParams = {
            inputs: [
                {
                    txId: 'ec62c785badb0ee693435841d35bd05da9c8a40aa2d568dddb0dd47410e7e78a',
                    vOut: 1,
                    address:
                        'kaspa:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x',
                    amount: 597700,
                },
                {
                    txId: 'fc72d896cbeb1ff804546952e46e06d95dc9b51ba3d579e5e5e6f7e8f9fa0b1c',
                    vOut: 0,
                    address:
                        'kaspa:qrcnkrtrjptghtrntvyqkqafj06f9tamn0pnqvelmt2vmz68yp4gqj5lnal2h',
                    amount: 400000,
                },
            ],
            outputs: [
                {
                    address:
                        'kaspa:qrcnkrtrjptghtrntvyqkqafj06f9tamn0pnqvelmt2vmz68yp4gqj5lnal2h',
                    amount: '500000',
                },
            ],
            address:
                'kaspa:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x',
            fee: '10000',
        };

        const result = await wallet.signTransaction({
            privateKey: privateKey,
            data: transferParams,
        });

        expect(result).toBeDefined();
        expect(typeof result).toBe('string');
    });

    test('signTransaction - transfer with invalid address in multiple inputs', async () => {
        const wallet = new KaspaWallet();
        const privateKey =
            'd636a23d4f49fe4e0d59fcf7a6c2ab3846ff2d3a54007b3817a11dff770d06ff';

        const transferParams = {
            inputs: [
                {
                    txId: 'ec62c785badb0ee693435841d35bd05da9c8a40aa2d568dddb0dd47410e7e78a',
                    vOut: 1,
                    address:
                        'kaspa:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x', // Valid
                    amount: 597700,
                },
                {
                    txId: 'fc72d896cbeb1ff804546952e46e06d95dc9b51ba3d579e5e5e6f7e8f9fa0b1c',
                    vOut: 0,
                    address: 'alice.near', // Invalid input address (NEAR)
                    amount: 400000,
                },
            ],
            outputs: [
                {
                    address:
                        'kaspa:qrcnkrtrjptghtrntvyqkqafj06f9tamn0pnqvelmt2vmz68yp4gqj5lnal2h',
                    amount: '987700',
                },
            ],
            address:
                'kaspa:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x',
            fee: '10000',
        };

        try {
            await wallet.signTransaction({
                privateKey: privateKey,
                data: transferParams,
            });
            expect(true).toBe(false); // Should not reach here
        } catch (e) {
            expect(e).toBeDefined();
        }
    });

    test('signTransaction - transfer with invalid address in multiple outputs', async () => {
        const wallet = new KaspaWallet();
        const privateKey =
            'd636a23d4f49fe4e0d59fcf7a6c2ab3846ff2d3a54007b3817a11dff770d06ff';

        const transferParams = {
            inputs: [
                {
                    txId: 'ec62c785badb0ee693435841d35bd05da9c8a40aa2d568dddb0dd47410e7e78a',
                    vOut: 1,
                    address:
                        'kaspa:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x',
                    amount: 597700,
                },
            ],
            outputs: [
                {
                    address:
                        'kaspa:qrcnkrtrjptghtrntvyqkqafj06f9tamn0pnqvelmt2vmz68yp4gqj5lnal2h', // Valid
                    amount: '300000',
                },
                {
                    address: 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq', // Invalid output address (Bitcoin)
                    amount: '287700',
                },
            ],
            address:
                'kaspa:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x',
            fee: '10000',
        };

        try {
            await wallet.signTransaction({
                privateKey: privateKey,
                data: transferParams,
            });
            expect(true).toBe(false); // Should not reach here
        } catch (e) {
            expect(e).toBeDefined();
        }
    });

    test('signTransaction - Error handling for malformed transaction data', async () => {
        const wallet = new KaspaWallet();
        const privateKey =
            'd636a23d4f49fe4e0d59fcf7a6c2ab3846ff2d3a54007b3817a11dff770d06ff';

        // Test with null data
        try {
            await wallet.signTransaction({
                privateKey: privateKey,
                data: null,
            });
            expect(true).toBe(false); // Should not reach here
        } catch (e) {
            expect(e).toBeDefined();
        }

        // Test with undefined data
        try {
            await wallet.signTransaction({
                privateKey: privateKey,
                data: undefined,
            });
            expect(true).toBe(false); // Should not reach here
        } catch (e) {
            expect(e).toBeDefined();
        }

        // Test with missing inputs
        try {
            await wallet.signTransaction({
                privateKey: privateKey,
                data: {
                    outputs: [
                        {
                            address:
                                'kaspa:qrcnkrtrjptghtrntvyqkqafj06f9tamn0pnqvelmt2vmz68yp4gqj5lnal2h',
                            amount: '587700',
                        },
                    ],
                    address:
                        'kaspa:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x',
                    fee: '10000',
                },
            });
            expect(true).toBe(false); // Should not reach here
        } catch (e) {
            expect(e).toBeDefined();
        }

        // Test with missing outputs
        try {
            await wallet.signTransaction({
                privateKey: privateKey,
                data: {
                    inputs: [
                        {
                            txId: 'ec62c785badb0ee693435841d35bd05da9c8a40aa2d568dddb0dd47410e7e78a',
                            vOut: 1,
                            address:
                                'kaspa:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x',
                            amount: 597700,
                        },
                    ],
                    address:
                        'kaspa:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x',
                    fee: '10000',
                },
            });
            expect(true).toBe(false); // Should not reach here
        } catch (e) {
            expect(e).toBeDefined();
        }
    });

    test('signTransaction - Error handling for invalid private key', async () => {
        const wallet = new KaspaWallet();

        const transferParams = {
            inputs: [
                {
                    txId: 'ec62c785badb0ee693435841d35bd05da9c8a40aa2d568dddb0dd47410e7e78a',
                    vOut: 1,
                    address:
                        'kaspa:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x',
                    amount: 597700,
                },
            ],
            outputs: [
                {
                    address:
                        'kaspa:qrcnkrtrjptghtrntvyqkqafj06f9tamn0pnqvelmt2vmz68yp4gqj5lnal2h',
                    amount: '587700',
                },
            ],
            address:
                'kaspa:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x',
            fee: '10000',
        };

        const invalidPrivateKeys = [
            '', // empty
            'invalid_hex',
            '0x', // too short
            '0000000000000000000000000000000000000000000000000000000000000000', // all zeros
            'ed25519:4ZBavqnpvLM5m96gvuSK5iGTFSo253TDzdcuiVUdyDY7njHADF5tv5LNHyfFnJiSNt7wthdxGjYNFL89vDAtqkmh', // NEAR format
        ];

        for (const invalidPrivateKey of invalidPrivateKeys) {
            try {
                await wallet.signTransaction({
                    privateKey: invalidPrivateKey,
                    data: transferParams,
                });
                expect(true).toBe(false); // Should not reach here
            } catch (e) {
                expect(e).toBeDefined();
            }
        }
    });

    test('signTransaction - Different Kaspa address formats', async () => {
        const wallet = new KaspaWallet();
        const privateKey =
            'd636a23d4f49fe4e0d59fcf7a6c2ab3846ff2d3a54007b3817a11dff770d06ff';

        const validKaspaFormats = [
            'kaspa:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x',
            'kaspa:qrcnkrtrjptghtrntvyqkqafj06f9tamn0pnqvelmt2vmz68yp4gqj5lnal2h',
        ];

        for (let i = 0; i < validKaspaFormats.length; i++) {
            const transferParams = {
                inputs: [
                    {
                        txId: 'ec62c785badb0ee693435841d35bd05da9c8a40aa2d568dddb0dd47410e7e78a',
                        vOut: 1,
                        address: validKaspaFormats[i],
                        amount: 597700,
                    },
                ],
                outputs: [
                    {
                        address:
                            validKaspaFormats[
                                (i + 1) % validKaspaFormats.length
                            ],
                        amount: '587700',
                    },
                ],
                address: validKaspaFormats[i],
                fee: '10000',
            };

            const result = await wallet.signTransaction({
                privateKey: privateKey,
                data: transferParams,
            });

            expect(result).toBeDefined();
            expect(typeof result).toBe('string');
        }
    });
});
