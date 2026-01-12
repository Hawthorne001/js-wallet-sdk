import {
    CalcTxHashParams,
    DerivePriKeyParams,
    GetDerivedPathParam,
    NewAddressData,
    NewAddressParams,
    SignTxParams,
    ValidAddressData,
    ValidAddressParams,
    BaseWallet,
    CalcTxHashError,
    GenPrivateKeyError,
    NewAddressError,
    SignMsgError,
    base,
    SignTxError,
    ValidPrivateKeyParams,
    ValidPrivateKeyData,
    SignCommonMsgParams,
    buildCommonSignMsg,
    SignType,
    InvalidPrivateKeyError,
    ValidAddressError,
} from '@okxweb3/coin-base';
import { signUtil } from '@okxweb3/crypto-lib';
import {
    SuiObjectRef,
    Ed25519Keypair,
    RawSigner,
    getAddressFromPrivate,
    TransactionBlock,
    TransactionBlockDataBuilder,
    encodeSuiPrivateKey,
    tryDecodeSuiPrivateKey,
    isValidSuiAddress,
} from './index';

export interface PaySuiTransaction {
    /**
     * use `provider.selectCoinSetWithCombinedBalanceGreaterThanOrEqual` to
     * derive a minimal set of coins with combined balance greater than or
     * equal to (sent amounts + gas budget).
     */
    inputCoins: SuiObjectRef[];
    recipient: string;
    amount: string;
    gasBudget: string;
    // gas price
    gasPrice: string;

    epoch?: number;
}

export const SUI_PRIVATE_KEY_PREFIX = 'suiprivkey';

export type SuiTransactionType = 'raw' | 'paySUI';

export type SuiSignData = {
    type: SuiTransactionType;
    data: string | PaySuiTransaction;
};

export class SuiWallet extends BaseWallet {
    async getDerivedPath(param: GetDerivedPathParam): Promise<any> {
        return `m/44'/784'/${param.index}'/0'/0'`;
    }

    async getRandomPrivateKey(): Promise<any> {
        try {
            const privateKeyHex = signUtil.ed25519.ed25519_getRandomPrivateKey(
                false,
                'hex'
            );
            return Promise.resolve(encodeSuiPrivateKey(privateKeyHex));
        } catch (e) {
            return Promise.reject(GenPrivateKeyError);
        }
    }

    async getDerivedPrivateKey(param: DerivePriKeyParams): Promise<any> {
        try {
            const privateKeyHex =
                await signUtil.ed25519.ed25519_getDerivedPrivateKey(
                    param.mnemonic,
                    param.hdPath,
                    false,
                    'hex'
                );
            return Promise.resolve(encodeSuiPrivateKey(privateKeyHex));
        } catch (e) {
            return Promise.reject(GenPrivateKeyError);
        }
    }

    getNewAddress(param: NewAddressParams): Promise<any> {
        try {
            const address = getAddressFromPrivate(
                tryDecodeSuiPrivateKey(param.privateKey)
            );
            let data: NewAddressData = {
                address: address.address,
                publicKey: address.publicKey,
            };
            return Promise.resolve(data);
        } catch (e) {
            return Promise.reject(NewAddressError);
        }
    }

    async validPrivateKey(param: ValidPrivateKeyParams): Promise<any> {
        let isValid = true;
        try {
            tryDecodeSuiPrivateKey(param.privateKey);
        } catch (e) {
            isValid = false;
        }
        const data: ValidPrivateKeyData = {
            isValid: isValid,
            privateKey: param.privateKey,
        };
        return Promise.resolve(data);
    }

    async signCommonMsg(params: SignCommonMsgParams): Promise<any> {
        const pri = tryDecodeSuiPrivateKey(params.privateKey);
        return super.signCommonMsg({
            privateKey: params.privateKey,
            privateKeyHex: pri,
            message: params.message,
            signType: SignType.ED25519,
            chainName: 'sui',
        });
    }

    async signMessage(param: SignTxParams): Promise<string> {
        if (!param.privateKey) {
            return Promise.reject(`${InvalidPrivateKeyError}: cannot be empty`);
        }

        const validResult = await this.validPrivateKey({
            privateKey: param.privateKey,
        });
        if (!validResult.isValid) {
            return Promise.reject(
                `${InvalidPrivateKeyError}: not valid private key`
            );
        }

        if (!(param.data instanceof Uint8Array)) {
            return Promise.reject(SignMsgError);
        }

        try {
            const message = param.data as Uint8Array;
            const keyPair = Ed25519Keypair.fromSeed(
                base.fromHex(tryDecodeSuiPrivateKey(param.privateKey))
            );
            const signer = new RawSigner(keyPair);
            return Promise.resolve(signer.signMessage({ message: message }));
        } catch (e) {
            return Promise.reject(SignTxError);
        }
    }

    async signTransaction(param: SignTxParams): Promise<any> {
        try {
            if (!param.privateKey) {
                return Promise.reject(InvalidPrivateKeyError);
            }
            const data: SuiSignData = param.data;
            const keyPair = Ed25519Keypair.fromSeed(
                base.fromHex(tryDecodeSuiPrivateKey(param.privateKey))
            );
            const signer = new RawSigner(keyPair);
            if (data.type == 'raw') {
                const s = data.data as string;
                const d = base.fromBase64(s);
                const signedTransaction = signer.signTransactionBlock({
                    transactionBlock: d,
                });
                return Promise.resolve(signedTransaction);
            } else if (data.type == 'paySUI') {
                const tx = new TransactionBlock();
                const s = data.data as PaySuiTransaction;
                if (s.inputCoins == undefined || s.inputCoins.length == 0) {
                    return Promise.reject(SignTxError);
                }
                // Validate recipient address
                const validation = await this.validAddress({
                    address: s.recipient,
                });
                if (!validation.isValid) {
                    return Promise.reject(ValidAddressError);
                }
                tx.setGasPrice(BigInt(s.gasPrice));
                tx.setGasBudget(BigInt(s.gasBudget));
                if (s.epoch) {
                    tx.setExpiration({ Epoch: s.epoch });
                }
                tx.setGasPayment(s.inputCoins);
                return signer
                    .getAddress()
                    .then((sender) => {
                        tx.setSender(sender);
                        const coin = tx.splitCoins(tx.gas, [
                            tx.pure(BigInt(s.amount)),
                        ]);
                        tx.transferObjects([coin], tx.pure(s.recipient));
                        return tx
                            .build()
                            .then((transactionBlock) => {
                                const signedTransaction =
                                    signer.signTransactionBlock({
                                        transactionBlock: transactionBlock,
                                    });
                                return Promise.resolve(signedTransaction);
                            })
                            .catch((err) => Promise.reject(err));
                    })
                    .catch((err) => Promise.reject(err));
            }
            return Promise.reject(SignTxError);
        } catch (e) {
            return Promise.reject(SignTxError);
        }
    }

    validAddress(param: ValidAddressParams): Promise<any> {
        const isValid = isValidSuiAddress(param.address);

        let data: ValidAddressData = {
            isValid,
            address: param.address,
        };
        return Promise.resolve(data);
    }

    async calcTxHash(param: CalcTxHashParams): Promise<string> {
        try {
            const hash = TransactionBlockDataBuilder.getDigestFromBytes(
                base.fromBase64(param.data as string)
            );
            return Promise.resolve(hash);
        } catch (e) {
            return Promise.reject(CalcTxHashError);
        }
    }
}
