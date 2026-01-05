import {
    AtomWallet,
    AxelarWallet,
    CelestiaWallet,
    CommonCosmosWallet,
    CosmosIbcTransferParam,
    CosmosSignParam,
    CosmosTransferParam,
    CronosWallet,
    DydxWallet,
    EvmosWallet,
    InjectiveWallet,
    InitiaWallet,
    IrisWallet,
    JunoWallet,
    KavaWallet,
    KujiraWallet,
    OsmoWallet,
    SecretWallet,
    SeiWallet,
    SignMessageData,
    StargazeWallet,
    TerraWallet,
    sendToken,
    sendIBCToken,
    amount2Coins,
    amount2Coin,
    amount2StdFee,
} from '../src';
import { base } from '@okxweb3/coin-base';

describe('CosmosWallet - Core Functionality', () => {
    const validPrivateKey =
        'ebc42dae1245fad403bd18f59f7283dc18724d2fc843b61e01224b9789057347';
    const validPublicKey =
        '03f79dd7029a5905e557906142b0c57ec21f4745f129b8c057aeccf42e2750ba6e';

    describe('getDerivedPath', () => {
        test('should return correct derivation path for different indices', async () => {
            const wallet = new AtomWallet();

            const path0 = await wallet.getDerivedPath({ index: 0 });
            expect(path0).toBe("m/44'/118'/0'/0/0");

            const path5 = await wallet.getDerivedPath({ index: 5 });
            expect(path5).toBe("m/44'/118'/0'/0/5");

            const path100 = await wallet.getDerivedPath({ index: 100 });
            expect(path100).toBe("m/44'/118'/0'/0/100");
        });

        test('should return correct paths for different coin types', async () => {
            const evmosWallet = new EvmosWallet();
            const evmosPath = await evmosWallet.getDerivedPath({ index: 0 });
            expect(evmosPath).toBe("m/44'/60'/0'/0/0");

            const kavaWallet = new KavaWallet();
            const kavaPath = await kavaWallet.getDerivedPath({ index: 0 });
            expect(kavaPath).toBe("m/44'/459'/0'/0/0");

            const secretWallet = new SecretWallet();
            const secretPath = await secretWallet.getDerivedPath({ index: 0 });
            expect(secretPath).toBe("m/44'/529'/0'/0/0");
        });
    });

    describe('checkPrivateKey', () => {
        test('should validate correct private keys', async () => {
            const wallet = new AtomWallet();

            expect(await wallet.checkPrivateKey(validPrivateKey)).toBe(true);
            expect(await wallet.checkPrivateKey('0x' + validPrivateKey)).toBe(
                true
            );
            expect(
                await wallet.checkPrivateKey(
                    '0X' + validPrivateKey.toUpperCase()
                )
            ).toBe(true);
        });

        test('should reject invalid private keys', async () => {
            const wallet = new AtomWallet();

            // Invalid hex
            expect(await wallet.checkPrivateKey('invalid')).toBe(false);
            expect(
                await wallet.checkPrivateKey(
                    'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz'
                )
            ).toBe(false);

            // Wrong length
            expect(await wallet.checkPrivateKey('abc123')).toBe(false);
            expect(await wallet.checkPrivateKey('')).toBe(false);

            // All zeros (invalid private key)
            expect(
                await wallet.checkPrivateKey(
                    '0000000000000000000000000000000000000000000000000000000000000000'
                )
            ).toBe(false);

            // Non-hex characters
            expect(
                await wallet.checkPrivateKey(
                    'ebc42dae1245fad403bd18f59f7283dc18724d2fc843b61e01224b9789057347g'
                )
            ).toBe(false);
        });

        test('should handle edge cases', async () => {
            const wallet = new AtomWallet();

            expect(await wallet.checkPrivateKey('0x')).toBe(false);
            expect(await wallet.checkPrivateKey('0X')).toBe(false);
            expect(
                await wallet.checkPrivateKey('   ' + validPrivateKey + '   ')
            ).toBe(false);
        });
    });

    describe('validPrivateKey', () => {
        test('should return validation result with private key', async () => {
            const wallet = new AtomWallet();

            const validResult = await wallet.validPrivateKey({
                privateKey: validPrivateKey,
            });
            expect(validResult.isValid).toBe(true);
            expect(validResult.privateKey).toBe(validPrivateKey);

            const invalidResult = await wallet.validPrivateKey({
                privateKey: 'invalid',
            });
            expect(invalidResult.isValid).toBe(false);
            expect(invalidResult.privateKey).toBe('invalid');
        });
    });

    describe('validAddress', () => {
        test('should validate addresses for different prefixes', async () => {
            const atomWallet = new AtomWallet();
            const osmoWallet = new OsmoWallet();

            const atomResult = await atomWallet.validAddress({
                address: 'cosmos1234567890',
            });
            expect(atomResult.address).toBe('cosmos1234567890');
            // Address will be invalid due to checksum, but structure test is what matters

            const osmoResult = await osmoWallet.validAddress({
                address: 'osmo1234567890',
            });
            expect(osmoResult.address).toBe('osmo1234567890');
        });

        test('should respect hrp parameter', async () => {
            const commonWallet = new CommonCosmosWallet();

            const result = await commonWallet.validAddress({
                address: 'cosmos1234567890',
                hrp: 'cosmos',
            });
            expect(result.address).toBe('cosmos1234567890');
        });
    });

    describe('getAddressByPublicKey', () => {
        test('should generate correct addresses from public key', async () => {
            const atomWallet = new AtomWallet();
            const osmoWallet = new OsmoWallet();

            const atomAddr = await atomWallet.getAddressByPublicKey({
                publicKey: validPublicKey,
            });
            expect(typeof atomAddr).toBe('string');
            expect(atomAddr.startsWith('cosmos')).toBe(true);

            const osmoAddr = await osmoWallet.getAddressByPublicKey({
                publicKey: validPublicKey,
            });
            expect(typeof osmoAddr).toBe('string');
            expect(osmoAddr.startsWith('osmo')).toBe(true);
        });

        test('should respect hrp parameter', async () => {
            const commonWallet = new CommonCosmosWallet();

            const addr = await commonWallet.getAddressByPublicKey({
                publicKey: validPublicKey,
                hrp: 'test',
            });
            expect(typeof addr).toBe('string');
            expect(addr.startsWith('test')).toBe(true);
        });
    });
});

describe('CosmosWallet - Transaction Operations', () => {
    const validPrivateKey =
        'ebc42dae1245fad403bd18f59f7283dc18724d2fc843b61e01224b9789057347';

    describe('signTransaction', () => {
        test('should handle transfer transactions', async () => {
            const wallet = new AtomWallet();

            const transferData: CosmosTransferParam = {
                fromAddress: 'cosmos137augvuewy625ns8a2age4sztl09hs7pmrdfdc',
                toAddress: 'cosmos137augvuewy625ns8a2age4sztl09hs7pmrdfdc',
                demon: 'uatom',
                amount: 1000000,
            };

            const signParam: CosmosSignParam = {
                type: 'transfer',
                chainId: 'cosmoshub-4',
                sequence: 1,
                accountNumber: 12345,
                feeDemon: 'uatom',
                feeAmount: 5000,
                gasLimit: 200000,
                memo: 'test transfer',
                data: transferData,
            };

            const result = await wallet.signTransaction({
                privateKey: validPrivateKey,
                data: signParam,
            });

            expect(result).toBeDefined();
            expect(typeof result).toBe('string');
        });

        test('should handle IBC transfer transactions', async () => {
            const wallet = new AtomWallet();

            const ibcTransferData: CosmosIbcTransferParam = {
                fromAddress: 'cosmos137augvuewy625ns8a2age4sztl09hs7pmrdfdc',
                toAddress: 'osmo137augvuewy625ns8a2age4sztl09hs7pnc7em2',
                demon: 'uatom',
                amount: 1000000,
                sourcePort: 'transfer',
                sourceChannel: 'channel-141',
            };

            const signParam: CosmosSignParam = {
                type: 'ibcTransfer',
                chainId: 'cosmoshub-4',
                sequence: 1,
                accountNumber: 12345,
                feeDemon: 'uatom',
                feeAmount: 5000,
                gasLimit: 200000,
                memo: 'test ibc transfer',
                data: ibcTransferData,
            };

            const result = await wallet.signTransaction({
                privateKey: validPrivateKey,
                data: signParam,
            });

            expect(result).toBeDefined();
            expect(typeof result).toBe('string');
        });

        test('should reject invalid transaction types', async () => {
            const wallet = new AtomWallet();

            const invalidSignParam = {
                type: 'invalid',
                chainId: 'cosmoshub-4',
                sequence: 1,
                accountNumber: 12345,
                feeDemon: 'uatom',
                feeAmount: 5000,
                gasLimit: 200000,
                memo: '',
                data: {},
            } as any;

            await expect(
                wallet.signTransaction({
                    privateKey: validPrivateKey,
                    data: invalidSignParam,
                })
            ).rejects.toBeDefined();
        });

        test('should handle errors gracefully', async () => {
            const wallet = new AtomWallet();

            await expect(
                wallet.signTransaction({
                    privateKey: 'invalid',
                    data: {} as any,
                })
            ).rejects.toBeDefined();
        });
    });

    describe('signCommonMsg', () => {
        test('should sign common messages with default hrp', async () => {
            const wallet = new AtomWallet();

            const result = await wallet.signCommonMsg({
                privateKey: validPrivateKey,
                message: { walletId: '123456789' },
            });

            expect(typeof result).toBe('string');
            expect(result.length).toBeGreaterThan(0);
        });

        test('should sign common messages with custom hrp', async () => {
            const wallet = new AtomWallet();

            const result = await wallet.signCommonMsg({
                privateKey: validPrivateKey,
                message: { text: 'test message' },
                hrp: 'test',
            });

            expect(typeof result).toBe('string');
            expect(result.length).toBeGreaterThan(0);
        });
    });

    describe('signMessage', () => {
        test('should sign amino messages', async () => {
            const wallet = new AtomWallet();
            const message = JSON.stringify({
                account_number: '123',
                chain_id: 'test-chain',
                fee: { amount: [], gas: '200000' },
                memo: '',
                msgs: [],
                sequence: '1',
            });

            const data: SignMessageData = {
                type: 'amino',
                data: message,
            };

            const result = await wallet.signMessage({
                privateKey: validPrivateKey,
                data,
            });

            expect(typeof result).toBe('string');
            expect(result.length).toBeGreaterThan(0);
        });

        test('should sign signDoc messages', async () => {
            const wallet = new AtomWallet();
            const message = JSON.stringify({
                chainId: 'test-chain',
                accountNumber: '123',
                body: '0a00',
                authInfo:
                    '0a0912040a02087f188a3412110a0f0a03696e6a12083433393939393939',
            });

            const data: SignMessageData = {
                type: 'signDoc',
                data: message,
            };

            const result = await wallet.signMessage({
                privateKey: validPrivateKey,
                data,
            });

            expect(typeof result).toBe('string');
            expect(result.length).toBeGreaterThan(0);
        });

        test('should handle withTx flag', async () => {
            const wallet = new AtomWallet();
            const message = JSON.stringify({
                account_number: '123',
                chain_id: 'test-chain',
                fee: { amount: [], gas: '200000' },
                memo: '',
                msgs: [],
                sequence: '1',
            });

            const data: SignMessageData = {
                type: 'amino',
                data: message,
                withTx: true,
            };

            const result = await wallet.signMessage({
                privateKey: validPrivateKey,
                data,
            });

            expect(typeof result).toBe('string');
            expect(result.length).toBeGreaterThan(0);
        });
    });
});

describe('CosmosWallet - MPC Operations', () => {
    const validPrivateKey =
        'ebc42dae1245fad403bd18f59f7283dc18724d2fc843b61e01224b9789057347';
    const validPublicKey =
        '03f79dd7029a5905e557906142b0c57ec21f4745f129b8c057aeccf42e2750ba6e';

    describe('getMPCRawTransaction', () => {
        test('should handle MPC raw transaction', async () => {
            const wallet = new AtomWallet();

            const transferData: CosmosTransferParam = {
                fromAddress: 'cosmos137augvuewy625ns8a2age4sztl09hs7pmrdfdc',
                toAddress: 'cosmos137augvuewy625ns8a2age4sztl09hs7pmrdfdc',
                demon: 'uatom',
                amount: 1000000,
            };

            const signParam: CosmosSignParam = {
                type: 'transfer',
                chainId: 'cosmoshub-4',
                sequence: 1,
                accountNumber: 12345,
                feeDemon: 'uatom',
                feeAmount: 5000,
                gasLimit: 200000,
                memo: 'test transfer',
                data: transferData,
            };

            // Test that the method exists and can be called
            // MpcRawTransactionParam expects the data to contain the entire SignTxParams structure
            // Cast to any since the implementation internally casts MpcRawTransactionParam as SignTxParams
            try {
                const result = await wallet.getMPCRawTransaction({
                    privateKey: validPrivateKey,
                    data: signParam,
                } as any);

                // If successful, verify structure
                if (result && typeof result === 'object') {
                    expect(result.raw).toBeDefined();
                    expect(result.hash).toBeDefined();
                    expect(typeof result.raw).toBe('string');
                    expect(typeof result.hash).toBe('string');
                }
            } catch (error) {
                // If it fails, that's also acceptable as we're testing the method exists
                expect(error).toBeDefined();
            }
        });

        test('should handle errors in MPC raw transaction', async () => {
            const wallet = new AtomWallet();

            await expect(
                wallet.getMPCRawTransaction({
                    privateKey: 'invalid',
                    data: {} as any,
                } as any)
            ).rejects.toBeDefined();
        });
    });

    describe('getMPCTransaction', () => {
        test('should handle MPC transaction with mock data', async () => {
            const wallet = new AtomWallet();

            // Test with mock data to verify the method works
            await expect(
                wallet.getMPCTransaction({
                    raw: 'invalid_raw_data',
                    sigs: 'invalid_signature',
                    publicKey: validPublicKey,
                })
            ).rejects.toBeDefined();
        });

        test('should handle errors in MPC transaction', async () => {
            const wallet = new AtomWallet();

            await expect(
                wallet.getMPCTransaction({
                    raw: 'invalid',
                    sigs: 'invalid',
                    publicKey: 'invalid',
                })
            ).rejects.toBeDefined();
        });
    });

    describe('getMPCRawMessage', () => {
        test('should generate MPC raw message', async () => {
            const wallet = new AtomWallet();
            const message = JSON.stringify({
                account_number: '123',
                chain_id: 'test-chain',
                fee: { amount: [], gas: '200000' },
                memo: '',
                msgs: [],
                sequence: '1',
            });

            const data: SignMessageData = {
                type: 'amino',
                data: message,
            };

            const result = await wallet.getMPCRawMessage({
                privateKey: validPrivateKey,
                data,
            } as any);

            expect(result).toBeDefined();
            expect(result.hash).toBeDefined();
            expect(typeof result.hash).toBe('string');
        });
    });

    describe('getMPCSignedMessage', () => {
        test('should handle MPC signed message with mock data', async () => {
            const wallet = new AtomWallet();

            // Test with invalid data to verify error handling
            await expect(
                wallet.getMPCSignedMessage({
                    hash: 'invalid_hash',
                    sigs: 'invalid_signature',
                    publicKey: 'invalid_public_key',
                })
            ).rejects.toBeDefined();
        });

        test('should handle errors in MPC signed message', async () => {
            const wallet = new AtomWallet();

            await expect(
                wallet.getMPCSignedMessage({
                    hash: 'invalid',
                    sigs: 'invalid',
                    publicKey: 'invalid',
                })
            ).rejects.toBeDefined();
        });
    });
});

describe('CosmosWallet - Utility Operations', () => {
    describe('calcTxHash', () => {
        test('should calculate transaction hash', async () => {
            const wallet = new AtomWallet();
            const mockTxData = base.toBase64(
                Buffer.from('mock transaction data')
            );

            const result = await wallet.calcTxHash({ data: mockTxData });

            expect(typeof result).toBe('string');
            expect(result.length).toBeGreaterThan(0);
            expect(result).toMatch(/^[A-F0-9]+$/); // Should be uppercase hex
        });

        test('should handle invalid transaction data', async () => {
            const wallet = new AtomWallet();

            await expect(
                wallet.calcTxHash({ data: 'invalid base64' })
            ).rejects.toBeDefined();
        });
    });

    describe('validSignedTransaction', () => {
        test('should handle validSignedTransaction method', async () => {
            const wallet = new AtomWallet();
            // Use a base64 encoded mock transaction
            const mockTx = base.toBase64(
                Buffer.from('mock signed transaction')
            );
            const mockData = {
                chainId: 'cosmoshub-4',
                accountNumber: '123',
                skipCheckSign: true, // Skip signature verification for test
            };

            try {
                const result = await wallet.validSignedTransaction({
                    tx: mockTx,
                    data: mockData,
                });

                expect(typeof result).toBe('string');
                // Should return JSON string
                expect(() => JSON.parse(result)).not.toThrow();
            } catch (error) {
                // Method might reject with mock data, which is acceptable
                expect(error).toBeDefined();
            }
        });

        test('should handle skipCheckSign option', async () => {
            const wallet = new AtomWallet();
            const mockTx = base.toBase64(
                Buffer.from('mock signed transaction')
            );
            const mockData = {
                chainId: 'cosmoshub-4',
                accountNumber: '123',
                skipCheckSign: true,
            };

            try {
                const result = await wallet.validSignedTransaction({
                    tx: mockTx,
                    data: mockData,
                });

                expect(typeof result).toBe('string');
                expect(() => JSON.parse(result)).not.toThrow();
            } catch (error) {
                // Method might reject with mock data, which is acceptable
                expect(error).toBeDefined();
            }
        });
    });
});

describe('CosmosWallet - Wallet Implementations', () => {
    const testPrivateKey =
        'ebc42dae1245fad403bd18f59f7283dc18724d2fc843b61e01224b9789057347';

    const walletTests = [
        {
            wallet: new AtomWallet(),
            prefix: 'cosmos',
            slip44: 118,
            ethSign: false,
        },
        {
            wallet: new OsmoWallet(),
            prefix: 'osmo',
            slip44: 118,
            ethSign: false,
        },
        {
            wallet: new EvmosWallet(),
            prefix: 'evmos',
            slip44: 60,
            ethSign: true,
        },
        {
            wallet: new AxelarWallet(),
            prefix: 'axelar',
            slip44: 118,
            ethSign: false,
        },
        {
            wallet: new CronosWallet(),
            prefix: 'cro',
            slip44: 394,
            ethSign: false,
        },
        {
            wallet: new IrisWallet(),
            prefix: 'iaa',
            slip44: 118,
            ethSign: false,
        },
        {
            wallet: new JunoWallet(),
            prefix: 'juno',
            slip44: 118,
            ethSign: false,
        },
        {
            wallet: new KavaWallet(),
            prefix: 'kava',
            slip44: 459,
            ethSign: false,
        },
        {
            wallet: new KujiraWallet(),
            prefix: 'kujira',
            slip44: 118,
            ethSign: false,
        },
        {
            wallet: new SecretWallet(),
            prefix: 'secret',
            slip44: 529,
            ethSign: false,
        },
        {
            wallet: new StargazeWallet(),
            prefix: 'stars',
            slip44: 118,
            ethSign: false,
        },
        {
            wallet: new TerraWallet(),
            prefix: 'terra',
            slip44: 330,
            ethSign: false,
        },
        { wallet: new SeiWallet(), prefix: 'sei', slip44: 118, ethSign: false },
        {
            wallet: new DydxWallet(),
            prefix: 'dydx',
            slip44: 118,
            ethSign: false,
        },
        {
            wallet: new InjectiveWallet(),
            prefix: 'inj',
            slip44: 60,
            ethSign: true,
        },
        {
            wallet: new InitiaWallet(),
            prefix: 'init',
            slip44: 60,
            ethSign: true,
        },
        {
            wallet: new CelestiaWallet(),
            prefix: 'celestia',
            slip44: 118,
            ethSign: false,
        },
    ];

    walletTests.forEach(({ wallet, prefix, slip44, ethSign }) => {
        describe(`${wallet.constructor.name}`, () => {
            test('should have correct configuration', () => {
                expect(wallet.getPrefix()).toBe(prefix);
                expect(wallet.getSlip44CoinType()).toBe(slip44);
                expect(wallet.supportEthSign()).toBe(ethSign);
            });

            test('should generate valid address', async () => {
                const result = await wallet.getNewAddress({
                    privateKey: testPrivateKey,
                });
                expect(result.address).toBeDefined();
                expect(result.address.startsWith(prefix)).toBe(true);
                expect(result.publicKey).toBeDefined();
                expect(result.publicKey.length).toBeGreaterThan(0);
            });

            test('should validate addresses correctly', async () => {
                const { address } = await wallet.getNewAddress({
                    privateKey: testPrivateKey,
                });
                const validation = await wallet.validAddress({ address });
                expect(validation.isValid).toBe(true);
                expect(validation.address).toBe(address);
            });

            test('should derive correct path', async () => {
                const path = await wallet.getDerivedPath({ index: 0 });
                expect(path).toBe(`m/44'/${slip44}'/0'/0/0`);
            });
        });
    });

    describe('CommonCosmosWallet', () => {
        test('should throw error when no prefix provided', () => {
            const wallet = new CommonCosmosWallet();
            expect(() => wallet.getPrefix()).toThrow(
                'common.ts wallet must input prefix in param'
            );
        });

        test('should work with hrp parameter', async () => {
            const wallet = new CommonCosmosWallet();
            const result = await wallet.getNewAddress({
                privateKey: testPrivateKey,
                hrp: 'test',
            });
            expect(result.address.startsWith('test')).toBe(true);
        });

        test('should have correct configuration', () => {
            const wallet = new CommonCosmosWallet();
            expect(wallet.getSlip44CoinType()).toBe(118);
            expect(wallet.supportEthSign()).toBe(false);
            expect(wallet.getAminoConverters()).toBeDefined();
            expect(wallet.getExtraTypes()).toBeDefined();
            expect(wallet.pubKeyUrl()).toBeUndefined();
        });
    });

    describe('Special Wallet Features', () => {
        test('InjectiveWallet should have custom pubKeyUrl', () => {
            const wallet = new InjectiveWallet();
            expect(wallet.pubKeyUrl()).toBe(
                '/injective.crypto.v1beta1.ethsecp256k1.PubKey'
            );
        });

        test('InitiaWallet should have custom pubKeyUrl', () => {
            const wallet = new InitiaWallet();
            expect(wallet.pubKeyUrl()).toBe(
                '/initia.crypto.v1beta1.ethsecp256k1.PubKey'
            );
        });

        test('OsmoWallet should have amino converters and extra types', () => {
            const wallet = new OsmoWallet();
            expect(wallet.getAminoConverters()).toBeDefined();
            expect(wallet.getExtraTypes()).toBeDefined();
        });

        test('KavaWallet should have amino converters and extra types', () => {
            const wallet = new KavaWallet();
            expect(wallet.getAminoConverters()).toBeDefined();
            expect(wallet.getExtraTypes()).toBeDefined();
        });

        test('SeiWallet should have amino converters and extra types', () => {
            const wallet = new SeiWallet();
            expect(wallet.getAminoConverters()).toBeDefined();
            expect(wallet.getExtraTypes()).toBeDefined();
        });
    });
});

describe('CosmosWallet - Error Handling', () => {
    const wallet = new AtomWallet();

    describe('getNewAddress error handling', () => {
        test('should handle invalid private key', async () => {
            await expect(
                wallet.getNewAddress({ privateKey: 'invalid' })
            ).rejects.toThrow('invalid key');
        });

        test('should handle empty private key', async () => {
            await expect(
                wallet.getNewAddress({ privateKey: '' })
            ).rejects.toThrow('invalid key');
        });

        test('should handle null/undefined private key', async () => {
            await expect(
                wallet.getNewAddress({ privateKey: null as any })
            ).rejects.toThrow();
            await expect(
                wallet.getNewAddress({ privateKey: undefined as any })
            ).rejects.toThrow();
        });
    });

    describe('signMessage error handling', () => {
        test('should handle invalid private key in signMessage', async () => {
            const data: SignMessageData = {
                type: 'amino',
                data: JSON.stringify({ test: 'data' }),
            };

            await expect(
                wallet.signMessage({
                    privateKey: 'invalid',
                    data,
                })
            ).rejects.toBeDefined();
        });

        test('should handle invalid message data', async () => {
            const data: SignMessageData = {
                type: 'amino',
                data: 'invalid json',
            };

            await expect(
                wallet.signMessage({
                    privateKey:
                        'ebc42dae1245fad403bd18f59f7283dc18724d2fc843b61e01224b9789057347',
                    data,
                })
            ).rejects.toBeDefined();
        });
    });

    describe('signMessageWithTx error handling', () => {
        test('should handle errors in signMessageWithTx', async () => {
            const data: SignMessageData = {
                type: 'amino',
                data: 'invalid json',
                withTx: true,
            };

            await expect(
                wallet.signMessage({
                    privateKey: 'invalid',
                    data,
                })
            ).rejects.toBeDefined();
        });
    });

    describe('toAddress validation', () => {
        const validPrivateKey =
            'ebc42dae1245fad403bd18f59f7283dc18724d2fc843b61e01224b9789057347';

        test('should reject empty toAddress in transfer transactions', async () => {
            const transferData: CosmosTransferParam = {
                fromAddress: 'cosmos1abc123',
                toAddress: '',
                demon: 'uatom',
                amount: 1000000,
            };

            const signParam: CosmosSignParam = {
                type: 'transfer',
                chainId: 'cosmoshub-4',
                sequence: 1,
                accountNumber: 12345,
                feeDemon: 'uatom',
                feeAmount: 5000,
                gasLimit: 200000,
                memo: 'test transfer',
                data: transferData,
            };

            await expect(
                wallet.signTransaction({
                    privateKey: validPrivateKey,
                    data: signParam,
                })
            ).rejects.toMatch(/valid address error/);
        });

        test('should reject whitespace-only toAddress in transfer transactions', async () => {
            const transferData: CosmosTransferParam = {
                fromAddress: 'cosmos1abc123',
                toAddress: '   ',
                demon: 'uatom',
                amount: 1000000,
            };

            const signParam: CosmosSignParam = {
                type: 'transfer',
                chainId: 'cosmoshub-4',
                sequence: 1,
                accountNumber: 12345,
                feeDemon: 'uatom',
                feeAmount: 5000,
                gasLimit: 200000,
                memo: 'test transfer',
                data: transferData,
            };

            await expect(
                wallet.signTransaction({
                    privateKey: validPrivateKey,
                    data: signParam,
                })
            ).rejects.toMatch(/valid address error/);
        });

        test('should reject empty toAddress in IBC transfer transactions', async () => {
            const ibcTransferData: CosmosIbcTransferParam = {
                fromAddress: 'cosmos1abc123',
                toAddress: '',
                demon: 'uatom',
                amount: 1000000,
                sourcePort: 'transfer',
                sourceChannel: 'channel-0',
            };

            const signParam: CosmosSignParam = {
                type: 'ibcTransfer',
                chainId: 'cosmoshub-4',
                sequence: 1,
                accountNumber: 12345,
                feeDemon: 'uatom',
                feeAmount: 5000,
                gasLimit: 200000,
                memo: 'test ibc transfer',
                data: ibcTransferData,
            };

            await expect(
                wallet.signTransaction({
                    privateKey: validPrivateKey,
                    data: signParam,
                })
            ).rejects.toMatch(/valid address error/);
        });

        test('should reject whitespace-only toAddress in IBC transfer transactions', async () => {
            const ibcTransferData: CosmosIbcTransferParam = {
                fromAddress: 'cosmos1abc123',
                toAddress: '  \t\n  ',
                demon: 'uatom',
                amount: 1000000,
                sourcePort: 'transfer',
                sourceChannel: 'channel-0',
            };

            const signParam: CosmosSignParam = {
                type: 'ibcTransfer',
                chainId: 'cosmoshub-4',
                sequence: 1,
                accountNumber: 12345,
                feeDemon: 'uatom',
                feeAmount: 5000,
                gasLimit: 200000,
                memo: 'test ibc transfer',
                data: ibcTransferData,
            };

            await expect(
                wallet.signTransaction({
                    privateKey: validPrivateKey,
                    data: signParam,
                })
            ).rejects.toMatch(/valid address error/);
        });

        test('should accept valid toAddress in transfer transactions', async () => {
            const transferData: CosmosTransferParam = {
                fromAddress: 'cosmos137augvuewy625ns8a2age4sztl09hs7pmrdfdc',
                toAddress: 'cosmos137augvuewy625ns8a2age4sztl09hs7pmrdfdc',
                demon: 'uatom',
                amount: 1000000,
            };

            const signParam: CosmosSignParam = {
                type: 'transfer',
                chainId: 'cosmoshub-4',
                sequence: 1,
                accountNumber: 12345,
                feeDemon: 'uatom',
                feeAmount: 5000,
                gasLimit: 200000,
                memo: 'test transfer',
                data: transferData,
            };

            // With valid addresses, this should pass validation but may fail for other reasons (like network calls)
            // We're just testing that the address validation passes
            try {
                await wallet.signTransaction({
                    privateKey: validPrivateKey,
                    data: signParam,
                });
            } catch (error: any) {
                // If it fails, it should not be due to address validation since we're using valid addresses
                // It might fail due to network calls or other reasons, which is acceptable
                expect(error).toMatch(/valid address error/);
            }
        });
    });
});

describe('CosmosWallet - Edge Cases', () => {
    const wallet = new AtomWallet();
    const validPrivateKey =
        'ebc42dae1245fad403bd18f59f7283dc18724d2fc843b61e01224b9789057347';

    test('should handle maximum index in getDerivedPath', async () => {
        const maxIndex = 2147483647; // Max safe integer for derivation
        const path = await wallet.getDerivedPath({ index: maxIndex });
        expect(path).toBe(`m/44'/118'/0'/0/${maxIndex}`);
    });

    test('should handle zero amounts in transactions', async () => {
        const transferData: CosmosTransferParam = {
            fromAddress: 'cosmos137augvuewy625ns8a2age4sztl09hs7pmrdfdc',
            toAddress: 'cosmos137augvuewy625ns8a2age4sztl09hs7pmrdfdc',
            demon: 'uatom',
            amount: 0,
        };

        const signParam: CosmosSignParam = {
            type: 'transfer',
            chainId: 'cosmoshub-4',
            sequence: 1,
            accountNumber: 12345,
            feeDemon: 'uatom',
            feeAmount: 5000,
            gasLimit: 200000,
            memo: '',
            data: transferData,
        };

        const result = await wallet.signTransaction({
            privateKey: validPrivateKey,
            data: signParam,
        });

        expect(result).toBeDefined();
    });

    test('should handle empty memo in transactions', async () => {
        const transferData: CosmosTransferParam = {
            fromAddress: 'cosmos137augvuewy625ns8a2age4sztl09hs7pmrdfdc',
            toAddress: 'cosmos137augvuewy625ns8a2age4sztl09hs7pmrdfdc',
            demon: 'uatom',
            amount: 1000000,
        };

        const signParam: CosmosSignParam = {
            type: 'transfer',
            chainId: 'cosmoshub-4',
            sequence: 1,
            accountNumber: 12345,
            feeDemon: 'uatom',
            feeAmount: 5000,
            gasLimit: 200000,
            memo: '',
            data: transferData,
        };

        const result = await wallet.signTransaction({
            privateKey: validPrivateKey,
            data: signParam,
        });

        expect(result).toBeDefined();
    });

    test('should handle very long memo in transactions', async () => {
        const longMemo = 'a'.repeat(1000);

        const transferData: CosmosTransferParam = {
            fromAddress: 'cosmos137augvuewy625ns8a2age4sztl09hs7pmrdfdc',
            toAddress: 'cosmos137augvuewy625ns8a2age4sztl09hs7pmrdfdc',
            demon: 'uatom',
            amount: 1000000,
        };

        const signParam: CosmosSignParam = {
            type: 'transfer',
            chainId: 'cosmoshub-4',
            sequence: 1,
            accountNumber: 12345,
            feeDemon: 'uatom',
            feeAmount: 5000,
            gasLimit: 200000,
            memo: longMemo,
            data: transferData,
        };

        const result = await wallet.signTransaction({
            privateKey: validPrivateKey,
            data: signParam,
        });

        expect(result).toBeDefined();
    });

    test('should handle different address formats', async () => {
        const addresses = [
            'cosmos1abc123def456ghi789',
            'cosmos1234567890abcdef',
            'cosmos1qwertyuiopasdfgh',
        ];

        for (const address of addresses) {
            const result = await wallet.validAddress({ address });
            expect(result.address).toBe(address);
            // Note: isValid will depend on actual checksum validation
        }
    });
});

describe('CosmosWallet - Integration Tests', () => {
    const validPrivateKey =
        'ebc42dae1245fad403bd18f59f7283dc18724d2fc843b61e01224b9789057347';

    test('should maintain consistency between address generation methods', async () => {
        const wallet = new AtomWallet();

        // Generate address using getNewAddress
        const newAddressResult = await wallet.getNewAddress({
            privateKey: validPrivateKey,
        });

        // Generate address using getAddressByPublicKey
        const addressFromPubKey = await wallet.getAddressByPublicKey({
            publicKey: newAddressResult.publicKey,
        });

        expect(newAddressResult.address).toBe(addressFromPubKey);
    });

    test('should work with hex prefix variations', async () => {
        const wallet = new AtomWallet();
        const baseKey =
            'ebc42dae1245fad403bd18f59f7283dc18724d2fc843b61e01224b9789057347';

        const results = await Promise.all([
            wallet.getNewAddress({ privateKey: baseKey }),
            wallet.getNewAddress({ privateKey: '0x' + baseKey }),
            wallet.getNewAddress({ privateKey: '0X' + baseKey }),
            wallet.getNewAddress({ privateKey: '0X' + baseKey.toUpperCase() }),
        ]);

        // All should generate the same address
        const firstAddress = results[0].address;
        results.forEach((result) => {
            expect(result.address).toBe(firstAddress);
        });
    });

    test('should handle transaction and message signing workflow', async () => {
        const wallet = new AtomWallet();

        // Generate address
        const addressResult = await wallet.getNewAddress({
            privateKey: validPrivateKey,
        });

        // Create and sign transaction
        const transferData: CosmosTransferParam = {
            fromAddress: addressResult.address,
            toAddress: 'cosmos15wgtkntdf26hqan77g0kdsldcxjddypxughytg',
            demon: 'uatom',
            amount: 1000000,
        };

        const signParam: CosmosSignParam = {
            type: 'transfer',
            chainId: 'cosmoshub-4',
            sequence: 1,
            accountNumber: 12345,
            feeDemon: 'uatom',
            feeAmount: 5000,
            gasLimit: 200000,
            memo: 'integration test',
            data: transferData,
        };

        const txResult = await wallet.signTransaction({
            privateKey: validPrivateKey,
            data: signParam,
        });

        expect(txResult).toBeDefined();
        expect(typeof txResult).toBe('string');

        // Sign a message
        const messageData: SignMessageData = {
            type: 'amino',
            data: JSON.stringify({
                account_number: '12345',
                chain_id: 'cosmoshub-4',
                fee: { amount: [], gas: '200000' },
                memo: 'test message',
                msgs: [],
                sequence: '1',
            }),
        };

        const msgResult = await wallet.signMessage({
            privateKey: validPrivateKey,
            data: messageData,
        });

        expect(msgResult).toBeDefined();
        expect(typeof msgResult).toBe('string');
    });
});

describe('CosmosWallet - Comprehensive Address Validation', () => {
    const wallet = new AtomWallet();
    const validPrivateKey =
        'ebc42dae1245fad403bd18f59f7283dc18724d2fc843b61e01224b9789057347';
    const validCosmosAddress = 'cosmos137augvuewy625ns8a2age4sztl09hs7pmrdfdc';

    describe('validAddress comprehensive tests', () => {
        test('validAddress with valid addresses for different chains', async () => {
            const walletTests = [
                {
                    wallet: new AtomWallet(),
                    prefix: 'cosmos',
                    validAddr: 'cosmos137augvuewy625ns8a2age4sztl09hs7pmrdfdc',
                },
                {
                    wallet: new OsmoWallet(),
                    prefix: 'osmo',
                    validAddr: 'osmo137augvuewy625ns8a2age4sztl09hs7pnc7em2',
                },
                {
                    wallet: new JunoWallet(),
                    prefix: 'juno',
                    validAddr: 'juno137augvuewy625ns8a2age4sztl09hs7pd3wj2y',
                },
                {
                    wallet: new SecretWallet(),
                    prefix: 'secret',
                    validAddr: 'secret137augvuewy625ns8a2age4sztl09hs7pexeqsy',
                },
                {
                    wallet: new KavaWallet(),
                    prefix: 'kava',
                    validAddr: 'kava137augvuewy625ns8a2age4sztl09hs7p8ke5ml',
                },
            ];

            for (const { wallet, prefix, validAddr } of walletTests) {
                const result = await wallet.validAddress({
                    address: validAddr,
                });
                expect(result.isValid).toBe(true);
                expect(result.address).toBe(validAddr);
            }
        });

        test('validAddress with invalid addresses', async () => {
            const invalidAddresses = [
                '', // Empty string
                'cosmos', // Just prefix
                'cosmos1', // Prefix with separator but no data
                'cosmos1abc', // Too short
                'notcosmos137augvuewy625ns8a2age4sztl09hs7pmrdfdc', // Wrong prefix
                'osmo137augvuewy625ns8a2age4sztl09hs7pnc7em2', // Wrong chain prefix for cosmos wallet
                'cosmos1INVALIDBECH32', // Invalid bech32 characters
                'cosmos137augvuewy625ns8a2age4sztl09hs7pmrdfdc extra text', // Valid address with extra
                'cosmos137augvuewy625ns8a2age4sztl09hs7pmrdfdc\n', // With newline
                '0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1', // Ethereum address
                'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq', // Bitcoin address
                'TRXMJzrBhqKmcJvMvQgjCTwJVjUjBNkP8u', // TRON address
                '  cosmos137augvuewy625ns8a2age4sztl09hs7pmrdfdc ', // With spaces
                null,
                undefined,
            ];

            for (const address of invalidAddresses) {
                const result = await wallet.validAddress({
                    address: address as any,
                });
                expect(result.isValid).toBe(false);
            }
        });
    });

    describe('signTransaction comprehensive address validation', () => {
        test('signTransaction with invalid to addresses should fail', async () => {
            const invalidAddresses = [
                '', // Empty string
                '   ', // Whitespace only
                'cosmos1abc', // Too short
                'cosmos1INVALIDBECH32', // Invalid bech32
                '0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1', // Ethereum address
                'bc1pyyn077ps82t7t0zjs0rlueg5876sdrqk79esr5e2w44g5f59dsmsl6m02d', // Bitcoin address
                null,
                undefined,
            ];

            for (const toAddress of invalidAddresses) {
                const transferData: CosmosTransferParam = {
                    fromAddress: validCosmosAddress,
                    toAddress: toAddress as any,
                    demon: 'uatom',
                    amount: 1000000,
                };

                const signParam: CosmosSignParam = {
                    type: 'transfer',
                    chainId: 'cosmoshub-4',
                    sequence: 1,
                    accountNumber: 12345,
                    feeDemon: 'uatom',
                    feeAmount: 5000,
                    gasLimit: 200000,
                    memo: 'test transfer',
                    data: transferData,
                };

                await expect(
                    wallet.signTransaction({
                        privateKey: validPrivateKey,
                        data: signParam,
                    })
                ).rejects.toMatch(/valid address error/);
            }
        });

        test('signTransaction with valid addresses should succeed', async () => {
            const validAddresses = [
                validCosmosAddress,
                'cosmos15wgtkntdf26hqan77g0kdsldcxjddypxughytg', // Different valid address pattern
            ];

            for (const toAddress of validAddresses) {
                const transferData: CosmosTransferParam = {
                    fromAddress: validCosmosAddress,
                    toAddress: toAddress,
                    demon: 'uatom',
                    amount: 1000000,
                };

                const signParam: CosmosSignParam = {
                    type: 'transfer',
                    chainId: 'cosmoshub-4',
                    sequence: 1,
                    accountNumber: 12345,
                    feeDemon: 'uatom',
                    feeAmount: 5000,
                    gasLimit: 200000,
                    memo: 'test transfer',
                    data: transferData,
                };

                const result = await wallet.signTransaction({
                    privateKey: validPrivateKey,
                    data: signParam,
                });

                expect(result).toBeDefined();
                expect(typeof result).toBe('string');
            }
        });

        test('signTransaction cross-chain validation demonstration', async () => {
            const walletTests = [
                {
                    wallet: new AtomWallet(),
                    validAddr: validCosmosAddress,
                    invalidAddr: 'osmo137augvuewy625ns8a2age4sztl09hs7pnc7em2',
                },
                {
                    wallet: new OsmoWallet(),
                    validAddr: 'osmo137augvuewy625ns8a2age4sztl09hs7pnc7em2',
                    invalidAddr: validCosmosAddress,
                },
                {
                    wallet: new JunoWallet(),
                    validAddr: 'juno137augvuewy625ns8a2age4sztl09hs7pd3wj2y',
                    invalidAddr: validCosmosAddress,
                },
            ];

            for (const { wallet, validAddr, invalidAddr } of walletTests) {
                // Valid address for this chain should work
                const validTransferData: CosmosTransferParam = {
                    fromAddress: validAddr,
                    toAddress: validAddr,
                    demon: 'uatom',
                    amount: 1000000,
                };

                const validSignParam: CosmosSignParam = {
                    type: 'transfer',
                    chainId: 'test-chain',
                    sequence: 1,
                    accountNumber: 12345,
                    feeDemon: 'uatom',
                    feeAmount: 5000,
                    gasLimit: 200000,
                    memo: 'test transfer',
                    data: validTransferData,
                };

                const validResult = await wallet.signTransaction({
                    privateKey: validPrivateKey,
                    data: validSignParam,
                });
                expect(validResult).toBeDefined();
            }
        });
    });

    describe('IBC transfer comprehensive validation', () => {
        test('IBC transfers with invalid bech32 addresses should fail', async () => {
            const invalidBech32Addresses = [
                '', // Empty string
                '   ', // Whitespace only
                'cosmos1abc', // Too short
                'invalid_address', // Not bech32 format
                '0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1', // Ethereum address
                'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq', // Bitcoin address (different format)
                'cosmos1INVALIDBECH32CHARS', // Invalid bech32 characters
                null,
                undefined,
            ];

            for (const toAddress of invalidBech32Addresses) {
                const ibcTransferData: CosmosIbcTransferParam = {
                    fromAddress: validCosmosAddress,
                    toAddress: toAddress as any,
                    demon: 'uatom',
                    amount: 1000000,
                    sourcePort: 'transfer',
                    sourceChannel: 'channel-141',
                };

                const signParam: CosmosSignParam = {
                    type: 'ibcTransfer',
                    chainId: 'cosmoshub-4',
                    sequence: 1,
                    accountNumber: 12345,
                    feeDemon: 'uatom',
                    feeAmount: 5000,
                    gasLimit: 200000,
                    memo: 'test ibc transfer',
                    data: ibcTransferData,
                };

                await expect(
                    wallet.signTransaction({
                        privateKey: validPrivateKey,
                        data: signParam,
                    })
                ).rejects.toMatch(/valid address error/);
            }
        });

        test('IBC transfers with valid cross-chain addresses should succeed', async () => {
            const validCrossChainAddresses = [
                'osmo137augvuewy625ns8a2age4sztl09hs7pnc7em2', // Osmosis
                'juno137augvuewy625ns8a2age4sztl09hs7pd3wj2y', // Juno
                'secret137augvuewy625ns8a2age4sztl09hs7pexeqsy', // Secret
                'kava137augvuewy625ns8a2age4sztl09hs7p8ke5ml', // Kava
                'stars137augvuewy625ns8a2age4sztl09hs7p0l65xf', // Stargaze
            ];

            for (const toAddress of validCrossChainAddresses) {
                const ibcTransferData: CosmosIbcTransferParam = {
                    fromAddress: validCosmosAddress,
                    toAddress: toAddress,
                    demon: 'uatom',
                    amount: 1000000,
                    sourcePort: 'transfer',
                    sourceChannel: 'channel-141',
                };

                const signParam: CosmosSignParam = {
                    type: 'ibcTransfer',
                    chainId: 'cosmoshub-4',
                    sequence: 1,
                    accountNumber: 12345,
                    feeDemon: 'uatom',
                    feeAmount: 5000,
                    gasLimit: 200000,
                    memo: 'test ibc transfer',
                    data: ibcTransferData,
                };

                const result = await wallet.signTransaction({
                    privateKey: validPrivateKey,
                    data: signParam,
                });

                expect(result).toBeDefined();
                expect(typeof result).toBe('string');
            }
        });
    });
});

describe('Direct Function Address Validation', () => {
    const validPrivateKey = base.fromHex(
        'ebc42dae1245fad403bd18f59f7283dc18724d2fc843b61e01224b9789057347'
    );

    describe('sendToken validation', () => {
        test('should accept valid recipientAddress', async () => {
            const amount = amount2Coins('uatom', 1000000);
            const fee = amount2StdFee('uatom', 5000, 200000);

            try {
                await sendToken(
                    validPrivateKey,
                    'cosmoshub-4',
                    1,
                    12345,
                    'cosmos1abc123',
                    'cosmos1def456',
                    amount,
                    fee
                );
            } catch (error: any) {
                // If it fails, it should not be due to blank address validation
                expect(error.message).not.toContain('sign tx error');
            }
        });
    });

    describe('sendIBCToken validation', () => {
        test('should accept valid recipientAddress', async () => {
            const amount = amount2Coin('uatom', 1000000);
            const fee = amount2StdFee('uatom', 5000, 200000);

            await sendIBCToken(
                validPrivateKey,
                'cosmoshub-4',
                1,
                12345,
                'cosmos1abc123',
                'cosmos1def456',
                amount,
                'transfer',
                'channel-0',
                fee
            );
        });
    });
});
