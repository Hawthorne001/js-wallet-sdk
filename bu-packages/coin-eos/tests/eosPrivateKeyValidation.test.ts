import { EosWallet, WaxWallet } from '../src';
import { InvalidPrivateKeyError } from '@okxweb3/coin-base';

describe('eos wallet signTransaction privateKey validation', () => {
    const wallets: Array<[string, any]> = [
        ['EosWallet', new EosWallet()],
        ['WaxWallet', new WaxWallet()],
    ];

    for (const [name, wallet] of wallets) {
        test(`${name}: null privateKey should error`, async () => {
            const signParams: any = {
                // @ts-ignore
                privateKey: null,
                data: {},
            };
            await expect(wallet.signTransaction(signParams)).rejects.toEqual(
                InvalidPrivateKeyError
            );
        });
    }
});
