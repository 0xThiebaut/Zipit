const CRC_TABLE: number[] = [];
for (let i = 0; i < 256; i++) {
    let r = i;
    for (let j = 0; j < 8; j++) {
        if ((r & 1) === 1) {
            r = (r >>> 1) ^ 0xedb88320;
        } else {
            r >>>= 1;
        }
    }
    CRC_TABLE[i] = r;
}

export default function crc32(crc: number, byte: number): number {
    return crc >>> 8 ^ CRC_TABLE[(crc ^ byte) & 0xff]
}