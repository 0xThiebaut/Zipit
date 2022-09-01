import crc32 from "./crc";

export default class ZipCrypto {
    private readonly key: Uint8Array
    private key0: number
    private key1: number
    private key2: number

    constructor(key: Uint8Array) {
        this.key = key
        this.key0 = 305419896
        this.key1 = 591751049
        this.key2 = 878082192

        for (let b of this.key) {
            this.update_keys(b);
        }
    }


    private update_keys(b: number) {
        this.key0 = crc32(this.key0, b);
        this.key1 = ZipCrypto.uint32(this.key1 + (this.key0 & 0xFF));
        this.key1 = ZipCrypto.uint32(Math.imul(this.key1, 134775813) + 1);
        this.key2 = crc32(this.key2, this.key1 >>> 24);
    }

    encrypt(bytes: Uint8Array): Uint8Array {
        return bytes.map(byte => {
            const c = byte ^ this.update_byte()
            this.update_keys(byte)
            return c
        })
    }

    decrypt(bytes: Uint8Array): Uint8Array {
        return bytes.map(byte => {
            const c = byte ^ this.update_byte()
            this.update_keys(c)
            return c
        })
    }

    private update_byte(): number {
        const temp = this.key2 | 2;
        return ZipCrypto.uint8(Math.imul(temp, (temp ^ 1)) >>> 8)
    }

    private static uint8 = (n: number) => n & 0xFF;
    private static uint32 = (n: number) => n & 0xFFFFFFFF;
}
