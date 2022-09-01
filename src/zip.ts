import ZipCrypto from "./crypto";

interface Writeable<T> {
    write: (data: Uint8Array) => T
}

export default class ZipFile<T> {
    private readonly writer: Writeable<T>
    private readonly crypto?: ZipCrypto

    // File properties
    private file_name: number[] = "binary.vir".split('').map(c => c.charCodeAt(0));
    private file_uncompressed_size: number[] = [0x00, 0x00, 0x00, 0x00];
    private file_compressed_size: number[] = [0x00, 0x00, 0x00, 0x00];
    private file_crc: number[] = [0xFF, 0xFF, 0xFF, 0xFF];

    // Zip properties
    private zip_size: number = 0;


    // ZIP relies on a Writeable object as the write method may not be defined at the time of initialization.
    constructor(writer: Writeable<T>, name: string, size: number, crc: number, password?: Uint8Array) {
        if (password) {
            this.crypto = new ZipCrypto(password)
        }
        this.writer = writer


        this.file_name = name.split('').map(char => char.charCodeAt(0))
        this.file_uncompressed_size = this.uint32(size)
        this.file_compressed_size = this.crypto ? this.uint32(size + 12) : this.file_uncompressed_size
        this.file_crc = this.uint32(crc)

        // Compute local file header
        let general_purpose = 0x00
        if (this.crypto) {
            general_purpose |= 0x01
        }

        const local_file_header = new Uint8Array([
            0x50, 0x4B, 0x03, 0x04, // local file header signature
            0x14, 0x00,             // version
            general_purpose, 0x00,  // general purpose
            0x00, 0x00,             // compression (none)
            0x00, 0x00,             // file last modification time
            0x00, 0x00,             // file last modification date
            ...this.file_crc,      // CRC-32
            ...this.file_compressed_size, // compressed size
            ...this.file_uncompressed_size, // uncompressed size
            ...this.file_name_size(),              // file name length
            0x00, 0x00,             // extra data length
            ...this.file_name
        ]);

        this.zip_size = local_file_header.byteLength
        this.writer.write(local_file_header)

        // Compute local file encryption header
        if (this.crypto) {
            // Get random 12 bytes
            let local_file_encryption_header = new Uint8Array(12)
            local_file_encryption_header = window.crypto.getRandomValues(local_file_encryption_header)
            // Set the last byte to the last CRC byte
            local_file_encryption_header.set(this.file_crc.slice(-1), 11)
            // Encrypt the header
            local_file_encryption_header = this.crypto.encrypt(local_file_encryption_header)
            this.zip_size += local_file_encryption_header.byteLength
            this.writer.write(local_file_encryption_header)
        }
    }

    private file_name_size(): number[] {
        return this.uint16(this.file_name.length)
    }

    write(data: Uint8Array): T {
        this.zip_size += data.byteLength;
        // Store the data
        return this.writer.write(this.crypto ? this.crypto.encrypt(data) : data)
    }

    finalize(): T {

        let general_purpose = 0x00
        if (this.crypto) {
            general_purpose |= 0x01
        }

        const central_directory_file_header = [
            0x50, 0x4B, 0x01, 0x02, // central file header signature
            0x14, 0x00,             // version made by
            0x14, 0x00,             // version needed
            general_purpose, 0x00,             // general purpose
            0x00, 0x00,             // compression method (none)
            0x00, 0x00,             // file last modification time
            0x00, 0x00,             // file last modification date
            ...this.file_crc,              // CRC-32
            ...this.file_compressed_size,
            ...this.file_uncompressed_size,
            ...this.file_name_size(),
            0x00, 0x00,             // extra field length
            0x00, 0x00,             // file comment length
            0x00, 0x00,             // disk number
            0x00, 0x00,             // internal file attribute
            0x00, 0x00, 0x00, 0x00, // external file attribute
            0x00, 0x00, 0x00, 0x00, // relative offset
            ...this.file_name
        ]

        const central_directory_file_header_size = this.uint32(central_directory_file_header.length)

        const central_directory_file_header_offset = this.uint32(this.zip_size)

        const end_of_central_directory_record = [
            0x50, 0x4B, 0x05, 0x06, // End of central directory
            0x00, 0x00,//number of this discs
            0x00, 0x00,//disc start
            0x01, 0x00,//number of entries
            0x01, 0x00,//number of central directories
            ...central_directory_file_header_size,
            ...central_directory_file_header_offset,
            0x00, 0x00 // comment length
        ]

        return this.writer.write(new Uint8Array([...central_directory_file_header, ...end_of_central_directory_record]))
    }

    private uint32(n: number): number[] {
        return this.little_endian(n, 4)
    }

    private uint16(n: number): number[] {
        return this.little_endian(n, 2)
    }

    private little_endian(input: number, bytes: number): number[] {
        let little: number[] = []
        for (let i = 0; i < bytes; i++) {
            little[i] = (input >> (i * 8)) & 0xFF
        }
        return little
    }
}
