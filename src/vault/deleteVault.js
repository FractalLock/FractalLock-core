const fs = require("fs");
const sodium = require("libsodium-wrappers");
const secrets = require("secrets.js-grempe")
const path = require("path");

const {
    encryptFiles,
    buildPayload,
    buildManifest,
    encryptManifest
} = require("../internal/helpers")

const { openVault } = require("../internal/container")

async function deleteFromVault({vaultPath, sharePaths, fileName}) {
    await sodium.ready;
    console.log("DEBUG")
    console.log(fileName)
    if (!vaultPath || sharePaths.length === 0) {
        // throw new Error("Usage: delete <vault> <shares...> <filename>")
        throw new Error("No vault path and/or keyShares selected")
    }
    
    let vault
    try {
        vault = openVault(vaultPath)
    } catch (e) {
        console.error(e.message)
        return
    }
    
    const { fd, metadata, payloadStart } = vault
    const { threshold } = metadata.recovery
    
    let recoveredRootKey
    try {
        const shares = loadShares(sharePaths, threshold)
        recoveredRootKey = sodium.from_hex(
            secrets.combine(shares)
        )
        } catch (err) {
        console.error(err.message)
        fs.closeSync(fd)
        return
    }
    
    const prevVersion = metadata.versions.at(-1)
    
    // ---- Decrypt previous version key ----
    const prevVersionKey = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        sodium.from_base64(prevVersion.encryptedVersionKey.ciphertext),
        null,
        sodium.from_base64(prevVersion.encryptedVersionKey.nonce),
        recoveredRootKey
    )
    
    // ---- Read + decrypt manifest ----
    const m = prevVersion.payload.manifest
    const encManifest = Buffer.alloc(m.length)
    fs.readSync(fd, encManifest, 0, m.length, payloadStart + m.offset)
    
    const manifestPlain = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        encManifest,
        null,
        sodium.from_base64(m.nonce),
        prevVersionKey
    )
    
    const manifest = JSON.parse(Buffer.from(manifestPlain).toString("utf8"))
    
    sodium.memzero(prevVersionKey)
    sodium.memzero(manifestPlain)

    // ---- Remove file from manifest ----
    const before = manifest.files.length
    manifest.files = manifest.files.filter(f => f.name !== fileName)
    
    if (manifest.files.length === before) {
        fs.closeSync(fd)
        throw new Error(`File not found: ${fileName}`)
    }
    
    console.log(`Deleted ${fileName} (logical)`)

    // ---- Create new version key ----
    const newVersionKey = sodium.randombytes_buf(32)
    
    const { cipher: manifestCipher, nonce: manifestNonce } =
        encryptManifest(manifest, newVersionKey)
    
    // ---- Append encrypted manifest ----
    const fileSize = fs.statSync(vaultPath).size
    fs.appendFileSync(vaultPath, manifestCipher)
    
    const manifestOffset = fileSize - payloadStart
    
    // ---- Encrypt version key ----
    const vkNonce = sodium.randombytes_buf(
        sodium.crypto_aead_xchacha20poly1305_IETF_NPUBBYTES
    )
    
    const encryptedVk = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        newVersionKey,
        null,
        null,
        vkNonce,
        recoveredRootKey
    )
    
    // ---- Add new version ----
    metadata.versions.push({
        id: metadata.versions.length + 1,
        createdAt: new Date().toISOString(),
        encryptedVersionKey: {
        nonce: sodium.to_base64(vkNonce),
        ciphertext: sodium.to_base64(encryptedVk)
        },
        payload: {
        files: prevVersion.payload.files, // unchanged payload refs
        manifest: {
            nonce: sodium.to_base64(manifestNonce),
            offset: manifestOffset,
            length: manifestCipher.length
        }
        }
    })
    
    // ---- Rewrite metadata ----
    const newMetadataBuf = Buffer.from(JSON.stringify(metadata), "utf8")
    
    const newHeader = Buffer.alloc(16)
    newHeader.write("LOCKBOX\0", 0, "ascii")
    newHeader.writeUInt32LE(1, 8)
    newHeader.writeUInt32LE(newMetadataBuf.length, 12)
    
    const payload = fs.readFileSync(vaultPath).slice(payloadStart)
    
    fs.writeFileSync(
        vaultPath,
        Buffer.concat([newHeader, newMetadataBuf, payload])
    )
    
    sodium.memzero(recoveredRootKey)
    sodium.memzero(newVersionKey)
    fs.closeSync(fd)
    
    console.log("Logical delete complete")
    return {
        vaultPath: vaultPath,
        newVersionId: metadata.versions.length
    }
}

module.exports = deleteFromVault