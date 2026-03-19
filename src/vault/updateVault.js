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

const { openVault } = require("../internal/container")

async function updateVault({vaultPath, sharePaths, inputFiles}) {
    await sodium.ready;
    
    console.log(vaultPath, sharePaths, inputFiles)
    if (inputFiles.length === 0) {
        throw new Error("No input files provided")
    }

    const normalisedFiles = []
    for (const file of inputFiles) {
        if (typeof file === "string") {
            const data = fs.readFileSync(file)
            normalisedFiles.push({
                name: path.basename(file),
                data
            })
        } else {
            normalisedFiles.push({
                name: file.name,
                data: Buffer.isBuffer(file.data)
                ? file.data
                : Buffer.from(file.data)
            })
        }
    }

    if (!vaultPath || sharePaths.length === 0) {
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
        throw err
    }

    const prevVersion = metadata.versions[metadata.versions.length - 1]
    
    // decrypt previous version key
    const prevVersionKey = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        sodium.from_base64(prevVersion.encryptedVersionKey.ciphertext),
        null,
        sodium.from_base64(prevVersion.encryptedVersionKey.nonce),
        recoveredRootKey
    )

    // read encrypted previous manifest
    const prevManifestMeta = prevVersion.payload.manifest
    const encryptedPrevManifestBuf = Buffer.alloc(prevManifestMeta.length)

    fs.readSync(
        fd,
        encryptedPrevManifestBuf,
        0,
        prevManifestMeta.length,
        payloadStart + prevManifestMeta.offset
    )
    
    // decrypt previous manifest
    const prevManifestPlain = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        encryptedPrevManifestBuf,
        null,
        sodium.from_base64(prevManifestMeta.nonce),
        prevVersionKey
    )

    const prevManifest = JSON.parse(
        Buffer.from(prevManifestPlain).toString("utf8")
    )

    if (!prevManifest || !Array.isArray(prevManifest.files)) {
        fs.closeSync(fd)
        throw new Error("Failed to parse previous manifest")
    }

    sodium.memzero(encryptedPrevManifestBuf)
    sodium.memzero(prevManifestPlain)
    sodium.memzero(prevVersionKey)

    //Create a new version key
    const versionKey = sodium.randombytes_buf(32)

    //New files are encrypted using a new version key
    const encryptedFiles = encryptFiles(normalisedFiles, versionKey)

    // Build lookup of new files by name
    const newFilesByName = new Map()
    for (const f of encryptedFiles) {
        newFilesByName.set(f.originalName, f)
    }

    // Start from previous manifest
    const mergedFiles = []

    for (const entry of prevManifest.files) {
        if (!newFilesByName.has(entry.name)) {
            // keep old file reference
            mergedFiles.push(entry)
        }
    }

    // Add new/updated files
    for (const f of encryptedFiles) {
        mergedFiles.push({
            id: f.id,
            name: f.originalName
        })
    }

    const mergedManifest = {
        files: mergedFiles
    }

    console.log("merged manifest:")
    console.log(mergedManifest)

    //A merged manifest has been created that shows all the files that will be in this version
    //encrypted files for this version will just be the file that has been added
    const { cipher: manifestCipher, nonce: manifestNonce } = encryptManifest(mergedManifest, versionKey)
    // ---- BUILD PAYLOAD ----
    const { payloadBuffer, manifestMeta } = buildPayload(encryptedFiles, manifestCipher)
    //payload buffer now has the files and manifest in it
    //manifestMeta is the offset and length of the manifest

    const fileSize = fs.statSync(vaultPath).size

    // append new payload to end of file
    fs.appendFileSync(vaultPath, payloadBuffer)

    // compute base offset relative to payload start
    const newPayloadRelativeBase = fileSize - payloadStart

    // shift file offsets
    for (const f of encryptedFiles) {
        f.offset += newPayloadRelativeBase
    }

    // shift manifest offset
    manifestMeta.offset += newPayloadRelativeBase


    const vkNonce = sodium.randombytes_buf(
        sodium.crypto_aead_xchacha20poly1305_IETF_NPUBBYTES
    )
        
    const encryptedVk = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        versionKey,
        null,
        null,
        vkNonce,
        recoveredRootKey
    )
    const newVersionId = metadata.versions.length + 1
    metadata.versions.push({
        id: newVersionId,
        createdAt: new Date().toISOString(),
        fileCount: mergedFiles.length,
        encryptedVersionKey: {
            nonce: sodium.to_base64(vkNonce),
            ciphertext: sodium.to_base64(encryptedVk)
        },
        payload: {
            files: encryptedFiles.map(f => ({
                id: f.id,
                versionId: newVersionId,
                size: f.size,
                nonce: sodium.to_base64(f.nonce),
                offset: f.offset,
                length: f.ciphertext.length
            })),
            manifest: {
                nonce: sodium.to_base64(manifestNonce),
                offset: manifestMeta.offset,
                length: manifestMeta.length
            }
        }
    })

    console.log(metadata)
        
    const metadataJson = Buffer.from(JSON.stringify(metadata), "utf8")

    const header = Buffer.alloc(20)
    header.write("FRACTALLOCK\0", 0, "ascii")
    header.writeUInt32LE(1, 12)
    header.writeUInt32LE(metadataJson.length, 16)
    

    const payload = fs.readFileSync(vaultPath).slice(payloadStart)

    const container = Buffer.concat([
        header,
        metadataJson,
        payload
    ])


    fs.writeFileSync(vaultPath, container)
    fs.closeSync(fd)

    console.log("Vault updated")
    sodium.memzero(recoveredRootKey)
    sodium.memzero(versionKey)
    console.log("Root key destroyed from memory")

    return {
        vaultPath: vaultPath,
        newVersionId: metadata.versions.length
    }
    
}

module.exports = updateVault