import {
    KeyType,
    EosWallet,
    WaxWallet,
    getNewAddress,
    createAccount,
    toAssetString,
    transfer,
    stringToPrivateKey,
    privateKeyToLegacyString,
    stringToPublicKey,
    publicKeyToString,
    publicKeyToLegacyString,
    signMessage,
    verifySignature,
    signSerializedTransaction,
} from '../src';
import { signUtil } from '@okxweb3/crypto-lib';
import { base, InvalidPrivateKeyError, SignTxError } from '@okxweb3/coin-base';

describe('eos', () => {
    test('signCommonMsg', async () => {
        let wallet = new EosWallet();
        let sig = await wallet.signCommonMsg({
            privateKey: '5JUsJvGbjH1HQ9XhwPP2NuxPZrFNb95miDsfL1BjVrjJXu8qWmK',
            message: { walletId: '123456789' },
        });
        expect(sig).toEqual(
            '1b50854615dc25d0c856181f433789d6c2f8f88d1a15a95f14149d1e77ddd36761125dc2071414f3dc0281fb9c570392624309a3f83292ab2e874ef123f7c97b03,02afeca27ce8ad8627872e1b8dc2dfd2890520e07d90c0e06cc2c49fea358be9e2'
        );
        sig = await wallet.signCommonMsg({
            privateKey: '5JUsJvGbjH1HQ9XhwPP2NuxPZrFNb95miDsfL1BjVrjJXu8qWmK',
            message: { text: '123456789' },
        });
        expect(sig).toEqual(
            '1cc3ff3944439377583fd953ab2d90b2ededc64fe172092128cdc86764212f30c46d56e282047d34a2d0e8167e8cf3bb875b7f4547d939e2de929e958cadc227de,02afeca27ce8ad8627872e1b8dc2dfd2890520e07d90c0e06cc2c49fea358be9e2'
        );
    });
    test('private key getNewAddress', async () => {
        const privateKey =
            '5JUsJvGbjH1HQ9XhwPP2NuxPZrFNb95miDsfL1BjVrjJXu8qWmK';
        let wallet = new EosWallet();
        let expectedPublickey =
            'EOS6Dy7412h4XWxombV8fAqzDmE3EH9Yq2G6rP18Y7Anii2F7hhi6';
        expect(
            (await wallet.getNewAddress({ privateKey: privateKey })).publicKey
        ).toEqual(expectedPublickey);
    });

    test('private key', async () => {
        let wallet = new EosWallet();
        let key = await wallet.getRandomPrivateKey();
        console.log(key);
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
        const wallet = new EosWallet();
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
        const wallet = new EosWallet();
        const privateKey = await wallet.getRandomPrivateKey();
        let res = await wallet.validPrivateKey({ privateKey: privateKey });
        expect(res.isValid).toEqual(true);
        res = await wallet.validPrivateKey({ privateKey: privateKey + '1122' });
        expect(res.isValid).toEqual(false);
        res = await wallet.validPrivateKey({ privateKey: '' });
        expect(res.isValid).toEqual(false);
        res = await wallet.validPrivateKey({ privateKey: privateKey.slice(1) });
        expect(res.isValid).toEqual(false);

        res = await wallet.validPrivateKey({
            privateKey:
                '0000000000000000000000000000000000000000000000000000000000000000',
        });
        expect(res.isValid).toEqual(false);
    });

    test('address', async () => {
        const privateKey = stringToPrivateKey(
            '5KXHUFNZGMsNEFzzrCis1RJdtg5wjL941a1vAwAjmgHEektrZBj'
        );
        console.info(privateKey);

        const result = privateKeyToLegacyString(privateKey);
        console.info(result);

        const publicKey = stringToPublicKey(
            'EOS6sWWrSmaagPSxyvrqBKNd4Ta91PGbNVhG9oMK9kNwwzxpDuusu'
        );
        console.info(publicKey);

        const result2 = publicKeyToLegacyString(publicKey);
        console.info(result2);
    });

    test('getAmountString', async () => {
        let wallet = new EosWallet();
        let amount = await wallet.getAmountString('12345678');
        expect(amount).toBe('1234.5678 EOS');

        amount = await wallet.getAmountString('12345678', 6, 'EOSEOS');
        expect(amount).toBe('12.345678 EOSEOS');
    });

    test('transferToken2', async () => {
        const t = transfer({
            from: 'account1',
            to: 'account2',
            amount: toAssetString(100000000, 8, 'WAX'),
            memo: 'test',
            common: {
                chainId:
                    'f16b1833c747c43682f4386fca9cbb327929334a762755ebec17f6f23c9b8a12',
                privateKey: [
                    '5KXHUFNZGMsNEFzzrCis1RJdtg5wjL941a1vAwAjmgHEektrZBj',
                ],
                compression: true,
                refBlockNumber: 161052609,
                refBlockId:
                    '099977c1eecfd285461732ac745468341af6db935638dba8927dc525af6b0ad0',
                refBlockTimestamp: '2022-06-28T08:55:09.500',
                expireSeconds: 600,
            },
        });
        // {"signatures":["SIG_K1_K8vqJQTdrV6ohsdZTCVoE1NrrSrf9ivVV28DrQSTeraxuiGnCabLgJjKUgkQZWQrXtBR9Qv83css6EeiEd4BRpDJsPBAc6"],"compression":true,"packed_context_free_data":"78DA030000000001","packed_trx":"78DA733BB22BE960B99BB8D11A0620606458D664C2FCCA2014C80ED7B5397B9631E084C0C14833DFDF20D9156F8D8C14E1022FA1F4C3AFAC20498E70C70806300000869F19C2"}
        console.info(JSON.stringify(t));

        const t2 = transfer({
            from: 'account1',
            to: 'account2',
            amount: toAssetString(500000000, 8, 'WAX'),
            memo: 'test',
            common: {
                chainId:
                    'f16b1833c747c43682f4386fca9cbb327929334a762755ebec17f6f23c9b8a12',
                privateKey: [
                    '5KXHUFNZGMsNEFzzrCis1RJdtg5wjL941a1vAwAjmgHEektrZBj',
                ],
                compression: true,
                refBlockNumber: 161087501,
                refBlockId:
                    '099a000daf6df26a8ef6e3d34340b92d35bd939b34f4b000b69f91a091801abe',
                refBlockTimestamp: '2022-06-28T13:45:57.000',
                expireSeconds: 600,
            },
        });
        // {"signatures":["SIG_K1_JxPHx6GA3Ju5SfADJNMhFoZa6VUyseMmQWGD5b1fEZJRk7ZU8eW1WjT2LN9RDYnoN7dPqdNTk6sLTHqnWB5QHsER7uMpSw"],"compression":true,"packed_context_free_data":"78DA030000000001","packed_trx":"78DACBE5D89DC4CBD0F7EDF1650620606458D664C2FCCA2014C80ED7B5397B9631E084C0C14833DFDF20D9156F8D8C146102024E1C1089D4B3B220498E70C7080630000079C918D7"}
        console.info(JSON.stringify(t2));

        const t3 = transfer({
            from: 'account2',
            to: 'account1',
            memo: 'test',
            amount: toAssetString(100000000, 8, 'WAX'),
            common: {
                chainId:
                    'f16b1833c747c43682f4386fca9cbb327929334a762755ebec17f6f23c9b8a12',
                privateKey: [
                    '5KXHUFNZGMsNEFzzrCis1RJdtg5wjL941a1vAwAjmgHEektrZBj',
                ],
                compression: true,
                refBlockNumber: 161087501,
                refBlockId:
                    '099a000daf6df26a8ef6e3d34340b92d35bd939b34f4b000b69f91a091801abe',
                refBlockTimestamp: '2022-06-28T13:45:57.000',
                expireSeconds: 600,
            },
        });
        console.info(JSON.stringify(t3));
    });

    // creator: AccountName
    // newAccount: AccountName
    // pubKey: string
    // buyRam: BuyRAMParam
    // delegate: DelegateParam
    test('createAccount', async () => {
        const newPrivateKey = base.fromHex(
            '7f90612a7214632cfed0daee44cc9c8d2cfac8d6968976841d07b1b2596ab109'
        );
        const publicKey = signUtil.secp256k1.publicKeyCreate(
            newPrivateKey,
            true
        );

        const legacyKey = privateKeyToLegacyString({
            type: KeyType.k1,
            data: newPrivateKey,
        });
        console.info(legacyKey);

        const account1 = 'account1';
        const account2 = 'account2';
        const t = createAccount({
            creator: account1,
            newAccount: account2,
            pubKey: publicKeyToString({
                type: KeyType.k1,
                data: publicKey,
            }),
            buyRam: {
                payer: account1,
                receiver: account2,
                quantity: toAssetString(100000000, 8, 'WAX'),
            },
            delegate: {
                from: account1,
                receiver: account2,
                stakeNet: toAssetString(100000000, 8, 'WAX'),
                stakeCPU: toAssetString(100000000, 8, 'WAX'),
                transfer: false,
            },
            common: {
                chainId:
                    'f16b1833c747c43682f4386fca9cbb327929334a762755ebec17f6f23c9b8a12',
                privateKey: [
                    '5KXHUFNZGMsNEFzzrCis1RJdtg5wjL941a1vAwAjmgHEektrZBj',
                ],
                compression: true,
                refBlockNumber: 161086853,
                refBlockId:
                    '0999fd853cc7e589c975e2555f4245de6bdf6ca5c9edba265ca2d599139b04c4',
                refBlockTimestamp: '2022-06-28T13:40:34.000',
                expireSeconds: 600,
            },
        });
        // {"signatures":["SIG_K1_Keig1AyTVeNbGmLvS3N46goCakypBLyA6D9mioFmSkTD1QExiYdksGnZG4MRPCkKYTk8ffgkoCPjAfF6uwWUFWDPJXKffd"],"compression":true,"packed_context_free_data":"78DA030000000001","packed_trx":"78DAD362DF9DD4FAF764E9A35006206006110CAF0C42191CE6CD524AD9318B31E084C0C14833DFDF20F1156F8D8CD26002024E1C609A1128C1C8C0B43AE4AAC88B9063DBAF369DF99B681367B69669B9DD7EF67B1F9CD73B7C9CF2FAC4218832A295C2DDC160AF25BD6C9117863B0CD1DDC1F0F02B2B489223DC3102AC1B9D8F309281C1A378AF1D86910A048D0400549763BC"}
        console.info(JSON.stringify(t));
    });

    test('getNewAddress', async () => {
        const account1 = 'account1';
        const account2 = 'account2';
        const t = getNewAddress(
            account1,
            account2,
            '5KXHUFNZGMsNEFzzrCis1RJdtg5wjL941a1vAwAjmgHEektrZBj',
            100000000,
            100000000,
            100000000,
            false,
            8,
            'WAX',
            {
                chainId:
                    'f16b1833c747c43682f4386fca9cbb327929334a762755ebec17f6f23c9b8a12',
                privateKey: [
                    '5KXHUFNZGMsNEFzzrCis1RJdtg5wjL941a1vAwAjmgHEektrZBj',
                ],
                compression: true,
                refBlockNumber: 161086853,
                refBlockId:
                    '0999fd853cc7e589c975e2555f4245de6bdf6ca5c9edba265ca2d599139b04c4',
                refBlockTimestamp: '2022-06-28T13:40:34.000',
                expireSeconds: 600,
            }
        );
        console.info(JSON.stringify(t));
    });

    test('signMessage', async () => {
        const sig = signMessage(
            'f16b1833c747c43682f4386fca9cbb327929334a762755ebec17f6f23c9b8a12',
            '5KXHUFNZGMsNEFzzrCis1RJdtg5wjL941a1vAwAjmgHEektrZBj',
            '0x1234'
        );
        const pub = verifySignature(
            'f16b1833c747c43682f4386fca9cbb327929334a762755ebec17f6f23c9b8a12',
            sig,
            '0x1234'
        );
        expect(pub).toStrictEqual(
            'EOS5uHXgWKzQExL2Lhu9y8716B4dkYL4T6oUq8J9FrY6EDB79naYF'
        );
    });

    test('signSerializedTransaction', async () => {
        const sig = signSerializedTransaction(
            'f16b1833c747c43682f4386fca9cbb327929334a762755ebec17f6f23c9b8a12',
            ['5KXHUFNZGMsNEFzzrCis1RJdtg5wjL941a1vAwAjmgHEektrZBj'],
            '0x1234'
        );

        const pub = verifySignature(
            'f16b1833c747c43682f4386fca9cbb327929334a762755ebec17f6f23c9b8a12',
            sig[0],
            '0x1234'
        );
        console.info(pub);
        expect(pub).toStrictEqual(
            'EOS5uHXgWKzQExL2Lhu9y8716B4dkYL4T6oUq8J9FrY6EDB79naYF'
        );
    });
});

// Comprehensive validAddress tests similar to other wallets
describe('validAddress comprehensive tests', () => {
    const wallet = new EosWallet();

    test('validAddress with valid EOS account names', async () => {
        const validAccountNames = [
            { input: 'eosio.token', expected: 'eosio.token' },
            { input: 'myaccount123', expected: 'myaccount123' }, // numbers 1-5 are valid
            { input: 'user1', expected: 'user1' },
            { input: 'test.eos', expected: 'test.eos' },
            { input: 'a', expected: 'a' },
            { input: '12345', expected: '12345' },
            { input: 'abcdefghijkl', expected: 'abcdefghijkl' }, // 12 chars
            { input: 'test.z', expected: 'test.z' }, // z is valid after dot
            { input: '', expected: '' }, // Empty string is valid in EOS regex
        ];

        for (const { input, expected } of validAccountNames) {
            const result = await wallet.validAddress({ address: input });
            expect(result.isValid).toBe(true);
            expect(result.address).toBe(expected);
        }
    });

    test('validAddress with invalid EOS account names', async () => {
        const invalidAccountNames = [
            { address: 'UPPERCASE', reason: 'Contains uppercase letters' },
            { address: 'invalid@name', reason: 'Contains @ symbol' },
            { address: 'test_account', reason: 'Contains underscore' },
            { address: 'account-name', reason: 'Contains hyphen' },
            {
                address: 'toolongaccountname',
                reason: 'Too long (more than 13 chars)',
            },
            { address: 'test.6', reason: 'Invalid character 6 after dot' },
            { address: 'abcdefghijklm', reason: 'Too long (13 chars)' }, // This should be invalid
            { address: '0x123abc', reason: 'Ethereum-style address' },
            {
                address: '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
                reason: 'Bitcoin address',
            },
            {
                address: 'TRXMJzrBhqKmcJvMvQgjCTwJVjUjBNkP8u',
                reason: 'TRON address',
            },
            { address: 'test account', reason: 'Contains space' },
            { address: 'test\naccount', reason: 'Contains newline' },
            { address: null, reason: 'Null value' },
            { address: undefined, reason: 'Undefined value' },
        ];

        for (const { address, reason } of invalidAccountNames) {
            const result = await wallet.validAddress({
                address: address as any,
            });
            expect(result.isValid).toBe(false);
            expect(result.address).toBe(address);
        }
    });
});

// Comprehensive signTransaction error handling tests
describe('signTransaction comprehensive error handling', () => {
    const wallet = new EosWallet();
    const validPrivateKey =
        '5K2zfyGoKuo3ysvAUNKCWR9ZpHhvCbyzyNnNAvuWa71NtMEHGdE';
    const validAccountName = 'eosio.token';

    test('signTransaction with invalid private keys', async () => {
        const invalidPrivateKeys = [
            { key: '', reason: InvalidPrivateKeyError, shouldFail: true },
            { key: '0x', reason: SignTxError, shouldFail: true },
            { key: '124699', reason: SignTxError, shouldFail: true },
            {
                key: 'invalid_key_format',
                reason: SignTxError,
                shouldFail: true,
            },
            { key: 'EOS123INVALID', reason: SignTxError, shouldFail: true },
            { key: null, reason: InvalidPrivateKeyError, shouldFail: true },
            {
                key: undefined,
                reason: InvalidPrivateKeyError,
                shouldFail: true,
            },
        ];

        for (const { key, reason, shouldFail } of invalidPrivateKeys) {
            await expect(
                wallet.signTransaction({
                    privateKey: key as any,
                    data: {
                        type: 0, // transfer
                        from: validAccountName,
                        to: validAccountName,
                        amount: 1000,
                        precision: 4,
                        symbol: 'EOS',
                        memo: 'test',
                        common: {
                            chainId:
                                'aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906',
                            refBlockNum: 1,
                            refBlockPrefix: 452435776,
                            expiration: '2018-09-25T06:28:49',
                        },
                    },
                })
            ).rejects.toEqual(reason);
        }
    });

    test('signTransaction with invalid recipient addresses for transfers', async () => {
        const invalidRecipients = [
            { name: 'UPPERCASE', reason: 'Contains uppercase' },
            { name: 'invalid@name', reason: 'Contains @ symbol' },
            { name: 'test_account', reason: 'Contains underscore' },
            { name: 'account-name', reason: 'Contains hyphen' },
            {
                name: 'toolongaccountname',
                reason: 'Too long (more than 13 chars)',
            },
            { name: 'test.6', reason: 'Invalid character 6' },
            { name: '0x123abc', reason: 'Ethereum-style address' },
            {
                name: '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
                reason: 'Bitcoin address',
            },
            {
                name: 'TRXMJzrBhqKmcJvMvQgjCTwJVjUjBNkP8u',
                reason: 'TRON address',
            },
            { name: 'test account', reason: 'Contains space' },
            { name: 'test\naccount', reason: 'Contains newline' },
            { name: null, reason: 'Null value' },
            { name: undefined, reason: 'Undefined value' },
        ];

        for (const { name, reason } of invalidRecipients) {
            // Test invalid 'to' account (recipient validation)
            await expect(
                wallet.signTransaction({
                    privateKey: validPrivateKey,
                    data: {
                        type: 0, // transfer
                        from: 'alice', // Valid sender (not validated)
                        to: name, // Invalid recipient (should be validated)
                        amount: 1000,
                        precision: 4,
                        symbol: 'EOS',
                        memo: 'test',
                        common: {
                            chainId:
                                'aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906',
                            refBlockNum: 1,
                            refBlockPrefix: 452435776,
                            expiration: '2018-09-25T06:28:49',
                        },
                    },
                })
            ).rejects.toMatch(/valid address error/);
        }
    });

    test('signTransaction with invalid recipient addresses for create account', async () => {
        const invalidRecipients = [
            { name: 'UPPERCASE', reason: 'Contains uppercase' },
            { name: 'invalid@name', reason: 'Contains @ symbol' },
            {
                name: 'toolongaccountname',
                reason: 'Too long (more than 13 chars)',
            },
            { name: 'new account', reason: 'Contains space' },
            { name: null, reason: 'Null value' },
            { name: undefined, reason: 'Undefined value' },
        ];

        for (const { name, reason } of invalidRecipients) {
            // Test invalid newAccount (recipient in create account)
            await expect(
                wallet.signTransaction({
                    privateKey: validPrivateKey,
                    data: {
                        type: 1, // create account
                        creator: 'alice', // Valid creator (not validated)
                        newAccount: name, // Invalid recipient (should be validated)
                        pubKey: 'EOS6sWWrSmaagPSxyvrqBKNd4Ta91PGbNVhG9oMK9kNwwzxpDuusu',
                        buyRam: {
                            payer: 'alice',
                            receiver: 'bob',
                            quantity: 1000,
                        },
                        delegate: {
                            from: 'alice',
                            receiver: 'bob',
                            stakeNet: 1000,
                            stakeCPU: 1000,
                            transfer: false,
                        },
                        common: {
                            chainId:
                                'aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906',
                            refBlockNum: 1,
                            refBlockPrefix: 452435776,
                            expiration: '2018-09-25T06:28:49',
                        },
                    },
                })
            ).rejects.toMatch(/valid address error/);
        }
    });

    test('signTransaction validation demonstrates address checking', async () => {
        // Test that address validation works by demonstrating failure cases

        // Invalid 'from' account name should fail
        await expect(
            wallet.signTransaction({
                privateKey: validPrivateKey,
                data: {
                    type: 0, // transfer
                    from: 'INVALID', // Uppercase not allowed
                    to: 'eosio.token',
                    amount: 1000,
                    precision: 4,
                    symbol: 'EOS',
                    memo: 'test',
                    common: {
                        chainId:
                            'aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906',
                        refBlockNum: 1,
                        refBlockPrefix: 452435776,
                        expiration: '2018-09-25T06:28:49',
                    },
                },
            })
        ).rejects.toMatch(/sign tx error/);

        // Invalid 'to' account name should fail
        await expect(
            wallet.signTransaction({
                privateKey: validPrivateKey,
                data: {
                    type: 0, // transfer
                    from: 'eosio.token',
                    to: 'INVALID@NAME', // Invalid characters
                    amount: 1000,
                    precision: 4,
                    symbol: 'EOS',
                    memo: 'test',
                    common: {
                        chainId:
                            'aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906',
                        refBlockNum: 1,
                        refBlockPrefix: 452435776,
                        expiration: '2018-09-25T06:28:49',
                    },
                },
            })
        ).rejects.toMatch(/valid address error/);
    });
});
