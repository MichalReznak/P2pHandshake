import * as crypto from 'crypto'
import { getPublicKey } from '@noble/secp256k1';
import { utils } from 'ethereum-cryptography/secp256k1.js';
import { ecdsaSign, ecdh } from 'ethereum-cryptography/secp256k1-compat.js';

// Borrowed from @ethereumjs/devp2p
const concatKDF = (keyMaterial, keyLength) => {
    const SHA256BlockSize = 64;
    const reps = ((keyLength + 7) * 8) / (SHA256BlockSize * 8);

    const buffers = [];
    for (let counter = 0, tmp = Buffer.allocUnsafe(4); counter <= reps; ) {
        counter += 1;
        tmp.writeUInt32BE(counter, 0);
        buffers.push(crypto.createHash('sha256').update(tmp).update(keyMaterial).digest());
    }

    return Buffer.concat(buffers).slice(0, keyLength);
};

// Borrowed from @ethereumjs/devp2p
const ecdhX = (publicKey, privateKey) => {
    const hashfn = (x, y) => {
        const pubKey = new Uint8Array(33);
        pubKey[0] = (y[31] & 1) === 0 ? 0x02 : 0x03;
        pubKey.set(x, 1);
        return pubKey.slice(1);
    };
    return Buffer.from(ecdh(publicKey, privateKey, { hashfn }, Buffer.alloc(32)));
};

// Borrowed from @ethereumjs/devp2p
const taggedKdf = (remotePublicKey, data, sharedMacData = null) => {
    const privateKey = utils.randomPrivateKey();
    const publicKey = getPublicKey(privateKey, false);
    const key = concatKDF(ecdhX(remotePublicKey, privateKey), 32);
    const ekey = key.slice(0, 16); // encryption key

    // encrypt
    const IV = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-128-ctr', ekey, IV);
    const encryptedData = cipher.update(data);
    const dataIV = Buffer.concat([IV, encryptedData]);

    // create tag
    const mkey = crypto.createHash('sha256').update(key.slice(16, 32)).digest(); // MAC key
    const tag = crypto
        .createHmac('sha256', mkey)
        .update(Buffer.concat([dataIV, sharedMacData]))
        .digest();

    return Buffer.concat([publicKey, dataIV, tag]);
};

const input = JSON.parse(process.argv[2]);
switch (input.type) {
    case 'Ecdhx': {
        const privateKey = Buffer.from(input.privateKey, 'hex');
        const publicKey = Buffer.from(input.publicKey, 'hex');
        console.log(ecdhX(publicKey, privateKey).toString('hex'));
    }
        break;

    case 'EcdsaSign': {
        const ephemeralPrivateKey = Buffer.from(input.ephemeralPrivateKey, 'hex');
        const msg = Buffer.from(input.msg, 'hex');

        const sig = ecdsaSign(msg, ephemeralPrivateKey);
        console.log(Buffer.concat([Buffer.from(sig.signature), Buffer.from([sig.recid])]).toString('hex'));
    }
        break;

    case 'TaggedKdf': {
        const msg = Buffer.from(input.msg, 'hex');
        const sharedMacData = Buffer.from(input.macData, 'hex');
        const rpk = Buffer.from(input.remotePublicKey, 'hex');
        console.log(taggedKdf(rpk, msg, sharedMacData).toString('hex'));
    }
        break

    case 'ConcatKdf': {
        const publicKey = Buffer.from(input.msg, 'hex').slice(2).slice(0, 65);
        const privateKey = Buffer.from(input.privateKey, 'hex');

        // derive keys
        console.log(concatKDF(ecdhX(publicKey, privateKey), 32).slice(0, 16).toString('hex'));
    }
        break;

    default:
        throw new Error('Unreachable!');
}
