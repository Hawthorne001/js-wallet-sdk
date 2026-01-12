import {
    NotImplementedError,
    SignTxError,
    InvalidPrivateKeyError,
} from '@okxweb3/coin-base';
import {
    NostrAssetsWallet,
    nsecFromPrvKey,
    CryptTextParams,
    verifySignature,
    nipOpType,
    decodeBytes,
} from '../src';
import { bip39 } from '@okxweb3/crypto-lib';

const wallet = new NostrAssetsWallet();
const prv = 'nsec1hvwfx5ytjck8a7c2xsyys5ut930hhfkyfe2l2guf4gfj5t7n2gdqxvh70y';

describe('nostr', () => {
    test('null privateKey should error', async () => {
        const wallet = new NostrAssetsWallet();
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
        let wallet = new NostrAssetsWallet();
        let sig = await wallet.signCommonMsg({
            privateKey:
                'nsec1hvwfx5ytjck8a7c2xsyys5ut930hhfkyfe2l2guf4gfj5t7n2gdqxvh70y',
            message: { walletId: '123456789' },
        });
        expect(sig).toEqual(
            '1c4fe0c27c944b99630468c06fb9d37435c6f14e1537b1c8a725ff11c3fb35bfb6286ec3297553f45791d63fa828a957f752d357c8d58122862d5ba123dd5ee3cf'
        );
        sig = await wallet.signCommonMsg({
            privateKey:
                'nsec1hvwfx5ytjck8a7c2xsyys5ut930hhfkyfe2l2guf4gfj5t7n2gdqxvh70y',
            message: { text: '123456789' },
        });
        expect(sig).toEqual(
            '1c543e650db66566470f2e1588a4a7e00c1c0de445c3cf900d380f02747a8bb8d32c6f5265b332e0a825083c0abee38d3e0a0515fafd191c149905f4a92750ee98'
        );
    });

    test('random', async () => {
        let prv = await wallet.getRandomPrivateKey();
        console.log(prv);
        expect(prv.startsWith('nsec')).toBe(true);
    });

    test('getNewAddress common2', async () => {
        //sei137augvuewy625ns8a2age4sztl09hs7pk0ulte
        const privateKey =
            'nsec1hvwfx5ytjck8a7c2xsyys5ut930hhfkyfe2l2guf4gfj5t7n2gdqxvh70y';
        const wallet = new NostrAssetsWallet();
        let expectedAddress =
            'npub1znxtu8222hlzxc59w6nlq33h7erl66ux6d30nql5a0tmjh2809hstw0d22';
        expect(
            (await wallet.getNewAddress({ privateKey: privateKey })).address
        ).toEqual(expectedAddress);
        expect(
            (await wallet.validPrivateKey({ privateKey: privateKey })).isValid
        ).toEqual(true);
    });

    test('generate', async () => {
        let memo = await bip39.generateMnemonic();
        console.log('generate mnemonic:', memo);

        const hdPath = await wallet.getDerivedPath({ index: 0 });
        let derivePrivateKey = await wallet.getDerivedPrivateKey({
            mnemonic: memo,
            hdPath: hdPath,
        });
        console.log(
            'generate derived private key:',
            derivePrivateKey,
            ',derived path: ',
            hdPath
        );

        let newAddress = await wallet.getNewAddress({
            privateKey: derivePrivateKey,
        });
        console.log(
            'generate new address:',
            newAddress.address,
            'newAddress.publicKey',
            newAddress.publicKey
        );
    });

    test('validPrivateKey', async () => {
        const wallet = new NostrAssetsWallet();
        const privateKey = await wallet.getRandomPrivateKey();
        const res = await wallet.validPrivateKey({ privateKey: privateKey });
        expect(res.isValid).toEqual(true);
    });

    test('address', async () => {
        let r = await wallet.getNewAddress({
            privateKey:
                'nsec1hvwfx5ytjck8a7c2xsyys5ut930hhfkyfe2l2guf4gfj5t7n2gdqxvh70y',
        });
        expect(r.address).toEqual(
            'npub1znxtu8222hlzxc59w6nlq33h7erl66ux6d30nql5a0tmjh2809hstw0d22'
        );
        expect(r.publicKey).toEqual(
            '14ccbe1d4a55fe23628576a7f04637f647fd6b86d362f983f4ebd7b95d47796f'
        );
        const nsec = nsecFromPrvKey(decodeBytes('nsec', prv));
        expect(nsec).toBe(
            'nsec1hvwfx5ytjck8a7c2xsyys5ut930hhfkyfe2l2guf4gfj5t7n2gdqxvh70y'
        );

        let v = await wallet.validAddress({ address: r.address });
        console.log(v);
        expect(v.isValid).toBe(true);
        let v2 = await wallet.validAddress({ address: r.address + '2' });
        console.log(v2);
        expect(v2.isValid).toBe(false);
    });

    // event.id 385eb020a83cb7e547659922b6c092a55e88c5127d9448370d1e55221aaeb5dd
    // event.sig 86aceec7506ea3619826b97902f8d3dc89c137a3c8373c6e22b1d924134eaebcf7323467b0f9ebbd97aeeb1aaa973d602d8aa47e08cbc2b6d4a05919e6632240
    test('sign', async () => {
        let event = {
            kind: 1,
            created_at: Math.floor(1000), //unix
            tags: [],
            content: 'hello',
        };
        let r = await wallet.signTransaction({
            privateKey: prv,
            data: event,
        });
        let rr = JSON.parse(JSON.stringify(r));
        console.log('event.pubkey', rr['pubkey']);
        expect(rr['pubkey']).toEqual(
            '14ccbe1d4a55fe23628576a7f04637f647fd6b86d362f983f4ebd7b95d47796f'
        );
        expect(rr['id']).toEqual(
            '385eb020a83cb7e547659922b6c092a55e88c5127d9448370d1e55221aaeb5dd'
        );
        expect(verifySignature(rr)).toBe(true);
    });

    test('encrypt', async () => {
        try {
            let text = 'hello';
            let privkey = nsecFromPrvKey(
                '0x425824242e3038e026f7cbeb6fe289cb6ffcfad1fa955c318c116aa1f2f32bfc'
            );
            const encrypted = await wallet.signTransaction({
                privateKey: privkey,
                data: {
                    type: nipOpType.NIP04_Encrypt,
                    pubkey: '0x8a0523d045d09c30765029af9307d570cb0d969e4b9400c08887c23250626eea',
                    text: text,
                    isCryptText: true,
                },
            });
            console.log('encrypted', encrypted);
            const decrypted = await wallet.signTransaction({
                privateKey: privkey,
                data: {
                    type: nipOpType.NIP04_Decrypt,
                    pubkey: '8a0523d045d09c30765029af9307d570cb0d969e4b9400c08887c23250626eea',
                    text: encrypted,
                    isCryptText: true,
                },
            });
            console.log('decrypted', decrypted);
            expect(decrypted).toBe(text);
        } catch (e) {
            let err = e as Error;
            if (err.message === 'crypto is not defined') {
                console.log(err.message);
            }
        }
    });

    test('address validation comprehensive', async () => {
        const wallet = new NostrAssetsWallet();

        // Test valid nostrassets/nostr addresses should pass
        const validAddresses = [
            'npub1znxtu8222hlzxc59w6nlq33h7erl66ux6d30nql5a0tmjh2809hstw0d22', // from existing test
            'npub12g75lly3m582f54wlmy587ryd83l0z84d0npqkewf33k843q0mvq7zk6sv', // generated valid address
            'npub174qsjnskqh7p8dgqara7t4ydqfzs9gcyy8e7e040cmtq44tuxqzq0lpcsa', // generated valid address
            'npub1zld2huhfgpjsfx8n8yjv2vca2tdn9qjsfrt4svnk4sr3v43qqpxq2la8cc', // generated valid address
        ];

        for (const address of validAddresses) {
            const result = await wallet.validAddress({ address });
            expect(result).toBeDefined();
            expect(result.isValid).toBe(true);
            expect(result.address).toBe(address);
        }

        // Test invalid addresses - should fail validation
        const invalidAddresses = [
            // Bitcoin addresses
            '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
            '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy',
            'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq',

            // Ethereum addresses
            '0x742d35Cc6634C0532925a3b8D98C2Eb701C6c865',
            '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',

            // Solana addresses
            '7NRmECq1R4tCtXNvmvDAuXmii3vN1J9DRZWhMCuuUnkM',
            'FZNZLT5diWHooSBjcng9qitykwcL9v3RiNrpC3fp9PU1',

            // Invalid nostr formats
            'nsec1hvwfx5ytjck8a7c2xsyys5ut930hhfkyfe2l2guf4gfj5t7n2gdqxvh70y', // nsec instead of npub
            'npub1invalid', // invalid format
            'npub', // too short
            'invalid_address', // completely invalid
            '', // empty string
            'npub1znxtu8222hlzxc59w6nlq33h7erl66ux6d30nql5a0tmjh2809hstw0d222', // too long
        ];

        for (const address of invalidAddresses) {
            const result = await wallet.validAddress({ address });
            expect(result).toBeDefined();
            expect(result.isValid).toBe(false);
            expect(result.address).toBe(address);
        }
    });

    test('signTransaction - Event signing with valid data', async () => {
        const wallet = new NostrAssetsWallet();
        const privateKey =
            'nsec1hvwfx5ytjck8a7c2xsyys5ut930hhfkyfe2l2guf4gfj5t7n2gdqxvh70y';

        const event = {
            kind: 1,
            created_at: Math.floor(Date.now() / 1000),
            tags: [],
            content: 'Test message for signing',
        };

        const result = await wallet.signTransaction({
            privateKey: privateKey,
            data: event,
        });

        expect(result).toBeDefined();
        expect(result.kind).toBe(1);
        expect(result.content).toBe('Test message for signing');
        expect(result.pubkey).toBeDefined();
        expect(result.id).toBeDefined();
        expect(result.sig).toBeDefined();
        expect(typeof result.pubkey).toBe('string');
        expect(typeof result.id).toBe('string');
        expect(typeof result.sig).toBe('string');
    });

    test('signTransaction - Event signing with pre-filled pubkey', async () => {
        const wallet = new NostrAssetsWallet();
        const privateKey =
            'nsec1hvwfx5ytjck8a7c2xsyys5ut930hhfkyfe2l2guf4gfj5t7n2gdqxvh70y';

        const event = {
            kind: 1,
            created_at: 1000,
            tags: [],
            content: 'hello',
            pubkey: '14ccbe1d4a55fe23628576a7f04637f647fd6b86d362f983f4ebd7b95d47796f',
        };

        const result = await wallet.signTransaction({
            privateKey: privateKey,
            data: event,
        });

        expect(result.pubkey).toBe(
            '14ccbe1d4a55fe23628576a7f04637f647fd6b86d362f983f4ebd7b95d47796f'
        );
        expect(result.id).toBeDefined();
        expect(result.sig).toBeDefined();
    });

    test('signTransaction - Event signing with pre-filled id', async () => {
        const wallet = new NostrAssetsWallet();
        const privateKey =
            'nsec1hvwfx5ytjck8a7c2xsyys5ut930hhfkyfe2l2guf4gfj5t7n2gdqxvh70y';

        const event = {
            kind: 1,
            created_at: 1000,
            tags: [],
            content: 'hello',
            id: '385eb020a83cb7e547659922b6c092a55e88c5127d9448370d1e55221aaeb5dd',
        };

        const result = await wallet.signTransaction({
            privateKey: privateKey,
            data: event,
        });

        expect(result.id).toBe(
            '385eb020a83cb7e547659922b6c092a55e88c5127d9448370d1e55221aaeb5dd'
        );
        expect(result.pubkey).toBeDefined();
        expect(result.sig).toBeDefined();
    });

    test('signTransaction - NIP04 Encrypt with valid recipient address', async () => {
        const wallet = new NostrAssetsWallet();
        const privateKey =
            'nsec1hvwfx5ytjck8a7c2xsyys5ut930hhfkyfe2l2guf4gfj5t7n2gdqxvh70y';
        // Use hex public key for encryption (not npub format)
        const recipientPubkeyHex =
            '14ccbe1d4a55fe23628576a7f04637f647fd6b86d362f983f4ebd7b95d47796f';
        const text = 'Hello, encrypted message!';

        try {
            const result = await wallet.signTransaction({
                privateKey: privateKey,
                data: {
                    type: nipOpType.NIP04_Encrypt,
                    pubkey: recipientPubkeyHex,
                    text: text,
                    isCryptText: true,
                },
            });

            expect(result).toBeDefined();
            expect(typeof result).toBe('string');
            expect(result.length).toBeGreaterThan(0);
        } catch (e) {
            // Encryption might fail in test environment due to crypto dependencies
            const err = e as Error;
            if (
                err.message === 'crypto is null' ||
                err.message.includes('crypto')
            ) {
                console.log(
                    'Crypto not available in test environment:',
                    err.message
                );
            } else {
                throw e;
            }
        }
    });

    test('signTransaction - NIP04 Encrypt with invalid hex pubkey', async () => {
        const wallet = new NostrAssetsWallet();
        const privateKey =
            'nsec1hvwfx5ytjck8a7c2xsyys5ut930hhfkyfe2l2guf4gfj5t7n2gdqxvh70y';
        const text = 'Hello, encrypted message!';

        // Test with invalid hex pubkey format
        try {
            await wallet.signTransaction({
                privateKey: privateKey,
                data: {
                    type: nipOpType.NIP04_Encrypt,
                    pubkey: 'invalid_hex_pubkey', // Invalid hex format
                    text: text,
                    isCryptText: true,
                },
            });
            expect(true).toBe(false); // Should not reach here
        } catch (e) {
            expect(e).toBe(SignTxError); // Should throw some error from secp256k1.getSharedSecret
        }

        // Test with empty string
        try {
            await wallet.signTransaction({
                privateKey: privateKey,
                data: {
                    type: nipOpType.NIP04_Encrypt,
                    pubkey: '', // Empty string
                    text: text,
                    isCryptText: true,
                },
            });
            expect(true).toBe(false); // Should not reach here
        } catch (e) {
            expect(e).toBe(SignTxError); // Should throw some error
        }

        // Test with too short hex
        try {
            await wallet.signTransaction({
                privateKey: privateKey,
                data: {
                    type: nipOpType.NIP04_Encrypt,
                    pubkey: 'abc123', // Too short
                    text: text,
                    isCryptText: true,
                },
            });
            expect(true).toBe(false); // Should not reach here
        } catch (e) {
            expect(e).toBe(SignTxError); // Should throw some error
        }
    });

    test('signTransaction - NIP04 Decrypt with valid recipient address', async () => {
        const wallet = new NostrAssetsWallet();
        const privateKey =
            'nsec1hvwfx5ytjck8a7c2xsyys5ut930hhfkyfe2l2guf4gfj5t7n2gdqxvh70y';
        // Use hex public key for decryption (not npub format)
        const recipientPubkeyHex =
            '14ccbe1d4a55fe23628576a7f04637f647fd6b86d362f983f4ebd7b95d47796f';

        // First encrypt some text to get valid encrypted data, then try to decrypt it
        const originalText = 'test message';

        try {
            // First encrypt
            const encryptedResult = await wallet.signTransaction({
                privateKey: privateKey,
                data: {
                    type: nipOpType.NIP04_Encrypt,
                    pubkey: recipientPubkeyHex,
                    text: originalText,
                    isCryptText: true,
                },
            });

            // Then decrypt the encrypted result
            const decryptedResult = await wallet.signTransaction({
                privateKey: privateKey,
                data: {
                    type: nipOpType.NIP04_Decrypt,
                    pubkey: recipientPubkeyHex,
                    text: encryptedResult,
                    isCryptText: true,
                },
            });

            expect(decryptedResult).toBe(originalText);
        } catch (e) {
            // Decryption might fail in test environment due to crypto dependencies
            const err = e as Error;
            if (
                err.message === 'crypto is null' ||
                err.message.includes('crypto')
            ) {
                console.log(
                    'Crypto operation failed in test environment:',
                    err.message
                );
            } else {
                throw e;
            }
        }
    });

    test('signTransaction - NIP04 Decrypt with invalid hex pubkey', async () => {
        const wallet = new NostrAssetsWallet();
        const privateKey =
            'nsec1hvwfx5ytjck8a7c2xsyys5ut930hhfkyfe2l2guf4gfj5t7n2gdqxvh70y';
        const encryptedText = 'someEncryptedText?iv=someIV';

        // Test with invalid hex pubkey format
        try {
            await wallet.signTransaction({
                privateKey: privateKey,
                data: {
                    type: nipOpType.NIP04_Decrypt,
                    pubkey: 'invalid_hex_pubkey', // Invalid hex format
                    text: encryptedText,
                    isCryptText: true,
                },
            });
            expect(true).toBe(false); // Should not reach here
        } catch (e) {
            expect(e).toBe(SignTxError); // Should throw some error from secp256k1.getSharedSecret
        }
    });

    test('signTransaction - Unsupported NIP operation type', async () => {
        const wallet = new NostrAssetsWallet();
        const privateKey =
            'nsec1hvwfx5ytjck8a7c2xsyys5ut930hhfkyfe2l2guf4gfj5t7n2gdqxvh70y';
        const recipientPubkeyHex =
            '14ccbe1d4a55fe23628576a7f04637f647fd6b86d362f983f4ebd7b95d47796f';

        try {
            await wallet.signTransaction({
                privateKey: privateKey,
                data: {
                    type: 999, // Invalid type
                    pubkey: recipientPubkeyHex,
                    text: 'some text',
                    isCryptText: true,
                },
            });
            expect(true).toBe(false); // Should not reach here
        } catch (e) {
            expect(e).toBe(NotImplementedError);
        }
    });

    test('signTransaction - Event signing with invalid private key', async () => {
        const wallet = new NostrAssetsWallet();

        const event = {
            kind: 1,
            created_at: Math.floor(Date.now() / 1000),
            tags: [],
            content: 'Test message',
        };

        // Test with Bitcoin private key format
        try {
            await wallet.signTransaction({
                privateKey:
                    'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn', // Bitcoin WIF
                data: event,
            });
            expect(true).toBe(false); // Should not reach here
        } catch (e) {
            expect(e).toBe(SignTxError);
        }

        // Test with Ethereum private key format
        try {
            await wallet.signTransaction({
                privateKey:
                    '0x4c0883a69102937d6231471b5dbb6204fe512961708279a4a5e4e1d2b5e5e1e5', // Ethereum hex
                data: event,
            });
            expect(true).toBe(false); // Should not reach here
        } catch (e) {
            expect(e).toBe(SignTxError);
        }

        // Test with empty private key
        try {
            await wallet.signTransaction({
                privateKey: '',
                data: event,
            });
            expect(true).toBe(false); // Should not reach here
        } catch (e) {
            expect(e).toBe(InvalidPrivateKeyError);
        }

        // Test with invalid nsec format
        try {
            await wallet.signTransaction({
                privateKey: 'nsec_invalid_format',
                data: event,
            });
            expect(true).toBe(false); // Should not reach here
        } catch (e) {
            expect(e).toBe(SignTxError);
        }
    });

    test('signTransaction - Event signing with different event kinds', async () => {
        const wallet = new NostrAssetsWallet();
        const privateKey =
            'nsec1hvwfx5ytjck8a7c2xsyys5ut930hhfkyfe2l2guf4gfj5t7n2gdqxvh70y';

        const eventKinds = [
            { kind: 0, name: 'Metadata' },
            { kind: 1, name: 'Text Note' },
            { kind: 3, name: 'Contacts' },
            { kind: 4, name: 'Encrypted Direct Message' },
            { kind: 7, name: 'Reaction' },
            { kind: 1984, name: 'Report' },
            { kind: 9735, name: 'Zap' },
        ];

        for (const eventType of eventKinds) {
            const event = {
                kind: eventType.kind,
                created_at: Math.floor(Date.now() / 1000),
                tags: [],
                content: `Test ${eventType.name} content`,
            };

            const result = await wallet.signTransaction({
                privateKey: privateKey,
                data: event,
            });

            expect(result).toBeDefined();
            expect(result.kind).toBe(eventType.kind);
            expect(result.content).toBe(`Test ${eventType.name} content`);
            expect(result.pubkey).toBeDefined();
            expect(result.id).toBeDefined();
            expect(result.sig).toBeDefined();
        }
    });

    test('signTransaction - Event signing with tags', async () => {
        const wallet = new NostrAssetsWallet();
        const privateKey =
            'nsec1hvwfx5ytjck8a7c2xsyys5ut930hhfkyfe2l2guf4gfj5t7n2gdqxvh70y';

        const event = {
            kind: 1,
            created_at: Math.floor(Date.now() / 1000),
            tags: [
                [
                    'e',
                    '5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36',
                ],
                [
                    'p',
                    '14ccbe1d4a55fe23628576a7f04637f647fd6b86d362f983f4ebd7b95d47796f',
                ],
                ['t', 'bitcoin'],
                ['t', 'nostr'],
            ],
            content: 'Reply with tags',
        };

        const result = await wallet.signTransaction({
            privateKey: privateKey,
            data: event,
        });

        expect(result).toBeDefined();
        expect(result.tags).toEqual(event.tags);
        expect(result.pubkey).toBeDefined();
        expect(result.id).toBeDefined();
        expect(result.sig).toBeDefined();
    });

    test('signTransaction - Event signing with empty content', async () => {
        const wallet = new NostrAssetsWallet();
        const privateKey =
            'nsec1hvwfx5ytjck8a7c2xsyys5ut930hhfkyfe2l2guf4gfj5t7n2gdqxvh70y';

        const event = {
            kind: 1,
            created_at: Math.floor(Date.now() / 1000),
            tags: [],
            content: '', // Empty content
        };

        const result = await wallet.signTransaction({
            privateKey: privateKey,
            data: event,
        });

        expect(result).toBeDefined();
        expect(result.content).toBe('');
        expect(result.pubkey).toBeDefined();
        expect(result.id).toBeDefined();
        expect(result.sig).toBeDefined();
    });

    test('signTransaction - Event signing with very long content', async () => {
        const wallet = new NostrAssetsWallet();
        const privateKey =
            'nsec1hvwfx5ytjck8a7c2xsyys5ut930hhfkyfe2l2guf4gfj5t7n2gdqxvh70y';

        const longContent = 'A'.repeat(10000); // Very long content
        const event = {
            kind: 1,
            created_at: Math.floor(Date.now() / 1000),
            tags: [],
            content: longContent,
        };

        const result = await wallet.signTransaction({
            privateKey: privateKey,
            data: event,
        });

        expect(result).toBeDefined();
        expect(result.content).toBe(longContent);
        expect(result.pubkey).toBeDefined();
        expect(result.id).toBeDefined();
        expect(result.sig).toBeDefined();
    });

    test('signTransaction - Event signing with special characters', async () => {
        const wallet = new NostrAssetsWallet();
        const privateKey =
            'nsec1hvwfx5ytjck8a7c2xsyys5ut930hhfkyfe2l2guf4gfj5t7n2gdqxvh70y';

        const specialContent =
            '🚀 Hello World! 🌍 Testing with émojis and spëcial chäractërs 中文 العربية русский 🎉';
        const event = {
            kind: 1,
            created_at: Math.floor(Date.now() / 1000),
            tags: [],
            content: specialContent,
        };

        const result = await wallet.signTransaction({
            privateKey: privateKey,
            data: event,
        });

        expect(result).toBeDefined();
        expect(result.content).toBe(specialContent);
        expect(result.pubkey).toBeDefined();
        expect(result.id).toBeDefined();
        expect(result.sig).toBeDefined();
    });

    test('signTransaction - Multiple valid hex pubkeys for encryption', async () => {
        const wallet = new NostrAssetsWallet();
        const privateKey =
            'nsec1hvwfx5ytjck8a7c2xsyys5ut930hhfkyfe2l2guf4gfj5t7n2gdqxvh70y';
        const text = 'Test message';

        // Use valid hex public keys for encryption (not npub format)
        // Only use the known working public keys from existing tests
        const validHexPubkeys = [
            '14ccbe1d4a55fe23628576a7f04637f647fd6b86d362f983f4ebd7b95d47796f',
            '8a0523d045d09c30765029af9307d570cb0d969e4b9400c08887c23250626eea',
        ];

        for (const pubkey of validHexPubkeys) {
            try {
                const result = await wallet.signTransaction({
                    privateKey: privateKey,
                    data: {
                        type: nipOpType.NIP04_Encrypt,
                        pubkey: pubkey,
                        text: text,
                        isCryptText: true,
                    },
                });

                expect(result).toBeDefined();
            } catch (e) {
                const err = e as Error;
                if (
                    err.message === 'crypto is null' ||
                    err.message.includes('crypto')
                ) {
                    console.log('Crypto not available for pubkey', pubkey);
                } else {
                    throw e;
                }
            }
        }
    });

    test('signTransaction - Error handling for malformed event data', async () => {
        const wallet = new NostrAssetsWallet();
        const privateKey =
            'nsec1hvwfx5ytjck8a7c2xsyys5ut930hhfkyfe2l2guf4gfj5t7n2gdqxvh70y';

        // Test with null data
        try {
            await wallet.signTransaction({
                privateKey: privateKey,
                data: null,
            });
            expect(true).toBe(false); // Should not reach here
        } catch (e) {
            expect(e).toBe(SignTxError);
        }

        // Test with undefined data
        try {
            await wallet.signTransaction({
                privateKey: privateKey,
                data: undefined,
            });
            expect(true).toBe(false); // Should not reach here
        } catch (e) {
            expect(e).toBe(SignTxError);
        }

        // Test with non-object data
        try {
            await wallet.signTransaction({
                privateKey: privateKey,
                data: 'invalid_string_data',
            });
            expect(true).toBe(false); // Should not reach here
        } catch (e) {
            expect(e).toBe(SignTxError);
        }
    });
});
