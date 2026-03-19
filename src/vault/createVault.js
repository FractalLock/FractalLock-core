const fs = require("fs");
const sodium = require("libsodium-wrappers");
const secrets = require("secrets.js-grempe")
const path = require("path");

const {
    parseCreateArgs,
    encryptFiles,
    buildPayload,
    buildManifest,
    encryptManifest,
    loadShares
} = require("../internal/helpers")


async function createVault({vaultDir, shares, threshold, inputFiles}) {
    await sodium.ready;

    if (!vaultDir) {
        throw new Error('Vault directory not selected')
    }

    if (inputFiles.length === 0) {
        throw new Error("No input files provided")
    }
    
    if (threshold < 2) {
        throw new Error("Threshold must be at least 2")
    }
    
    if (shares < threshold) {
        throw new Error("Number of keyShares must be greater than or equal to threshold")
    }

    if (shares > 255) {
        throw new Error("Too many shares")
    }
    
    const vaultPath = path.join(vaultDir, 'myvault.frx')

    if (fs.existsSync(vaultPath)) {
        throw new Error('A vault already exists in this directory')
    }

    for (const filePath of inputFiles) {
        if (!fs.existsSync(filePath)) {
            throw new Error(`Input file does not exist: ${filePath}`)
        }
    }

    
    const files = inputFiles.map(filePath => ({
        path: filePath,
        data: fs.readFileSync(filePath)
    }))

    const rootKey = sodium.randombytes_buf(32)
    const versionKey = sodium.randombytes_buf(32)
    //Creates the file nonces and encrypts the files using the version key
    const encryptedFiles = encryptFiles(files, versionKey)

    
    //Creates the version key nonce and encrypts the version key using the root key
    const vkNonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_IETF_NPUBBYTES)
    const encryptedVk = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        versionKey,
        null,
        null,
        vkNonce,
        rootKey
    )
    
    //Creates the manifest nonce and encrypts the manifest using the version key
    // Manifest defines the logical contents of a version.
    // Files not present here are considered deleted,
    // even if their encrypted payload still exists.
    const manifest = buildManifest(encryptedFiles)
    
    const { cipher: manifestCipher, nonce: manifestNonce } = encryptManifest(manifest, versionKey)
    
    // ---- BUILD PAYLOAD ----
    // payload.files may include files from older versions.
    // versionId determines which versionKey decrypts them.
    const { payloadBuffer, manifestMeta } = buildPayload(encryptedFiles, manifestCipher)
    
    // ---- BUILD METADATA ----
    const metadata = {
        header: {
            magic: "FRACTALLOCK\0",
            formatVersion: 1,
            cipher: "xchacha20-poly1305"
        },
        
        recovery: {
            scheme: "shamir",
            threshold,
            shares,
            encoding: "hex"
        },
        
        versions: [
            {
                id: 1,
                createdAt: new Date().toISOString(),
                encryptedVersionKey: {
                    nonce: sodium.to_base64(vkNonce),
                    ciphertext: sodium.to_base64(encryptedVk)
                },
        
                payload: {
                    files: encryptedFiles.map(f => ({
                        
                        id: f.id,
                        versionId: 1,
                        size: f.size,
                        nonce: sodium.to_base64(f.nonce),
                        offset: f.offset,
                        length: f.length
                        
                    })),
                    manifest: {
                        nonce: sodium.to_base64(manifestNonce),
                        offset: manifestMeta.offset,
                        length: manifestMeta.length
                    }
                }
            }
        ]
    }

    const metadataJson = Buffer.from(JSON.stringify(metadata), "utf8")

    const header = Buffer.alloc(20)
    header.write("FRACTALLOCK\0", 0, "ascii")
    header.writeUInt32LE(1, 12)                // container version
    header.writeUInt32LE(metadataJson.length, 16)
    
    const container = Buffer.concat([
        header,
        metadataJson,
        payloadBuffer
    ])
        
    fs.writeFileSync(vaultPath, container, { flag: "wx" })
    // console.log("Vault written to myvault.frx")

    const rootKeyHex = sodium.to_hex(rootKey)
    const shareList = secrets.share(rootKeyHex, shares, threshold)
    // console.log("Shares generated:")
    // shareList.forEach((s,i) => {
    //     fs.writeFileSync(path.join(vaultDir, `share${i + 1}.txt`), s)
    //     // console.log(`share${i+1}: saved to share${i+1}.txt`)
    // })
    sodium.memzero(rootKey)
    sodium.memzero(versionKey)
    // console.log("Root key destroyed from memory")

    return {
        vaultPath: vaultPath,
        sharesGenerated: shareList.length,
        shares: shareList.map((share, index) => ({
            id: index + 1,
            data: share
        }))
    }
}


module.exports = createVault