import crypto from 'crypto';

// convert modules 
import { hexToU8a } from '@polkadot/util/hex/toU8a';
import { stringToU8a } from '@polkadot/util/string/toU8a';
import { u8aToHex } from '@polkadot/util/u8a/toHex';

// use for create ed25519 publickey
import { InfraSS58 } from 'infra-did-js';

export class slip10ED {
  static seed2hdnode(data: Uint8Array, seed: Uint8Array): [Uint8Array, Uint8Array] {
    const h = crypto.createHmac('sha512', seed).update(data).digest();
    const key = h.subarray(0, 32);
    const chaincode = h.subarray(32);
    return [key, chaincode];
  }
  static async derive(parent_key: Uint8Array, parent_chaincode: Uint8Array, i: number): Promise<[Uint8Array, Uint8Array]> {
    if (parent_key.length !== 32 || parent_chaincode.length !== 32) {
      throw new Error('length error');
    }
    const init_key = new Uint8Array(1);
    init_key.set([0x00]);
    const iarr = hexToU8a(i.toString(16));
    const d = new Uint8Array(init_key.length + parent_key.length + iarr.length);
    d.set(init_key);
    d.set(parent_key, init_key.length);
    d.set(iarr, init_key.length + parent_key.length);
    return this.seed2hdnode(d, parent_chaincode);
  }
  static fingerprint(pk: string): string {
    const sha256pk = crypto.createHash('sha256').update(hexToU8a(`0x${pk}`)).digest('hex');
    const pk160 = crypto.createHash('ripemd160').update(hexToU8a(sha256pk)).digest('hex');
    return pk160.slice(0, 8);
  }

  static async show_testvector(): Promise<void> {
    const name = 'Test vector 1';
    const privdev = 0x80000000;
    const derivationpath = [privdev + 0, 1, privdev + 2, 2, 1000000000];
    const seedhex = '0x000102030405060708090a0b0c0d0e0f';
    const curveName = 'ed25519';
    const seedmodifier = 'ed25519 seed';
    let [k, c] = this.seed2hdnode(hexToU8a(seedhex), stringToU8a(seedmodifier));
    const { publicKey } = await InfraSS58.createNewSS58DIDSet('space', undefined, u8aToHex(k));
    let p = '00' + publicKey.toJSON()['Ed25519'].slice(2);
    let fpr = '00000000';
    let path = 'm';
    let depth = 0;

    console.log(`
    ${name} for ${curveName}
    Seed(hex): ${seedhex}
    * master key Chain ${path}
    ** fingerprint: ${(fpr)}
    ** chain code: ${(u8aToHex(c))}
    ** private(sk): ${(u8aToHex(k))}
    ** public(pk): ${(p)}
    `);
    for (let i of derivationpath) {
      i = (i | privdev) >>> 0;
      fpr = this.fingerprint(p);
      depth += 1;
      path += `/${i & (privdev - 1)}h`;
      [k, c] = await this.derive(k, c, i);
      const { publicKey } = await InfraSS58.createNewSS58DIDSet('space', undefined, u8aToHex(k));
      p = '00' + publicKey.toJSON()['Ed25519'].slice(2);

      console.log(`
    * ${depth}depth Chain ${path}
    ** fingerprint: ${(fpr)}
    ** chain code: ${(u8aToHex(c))}
    ** private(sk): ${(u8aToHex(k))}
    ** public(pk): ${(p)}
    `);
    }
  }
}
