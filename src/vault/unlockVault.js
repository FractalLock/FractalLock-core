// Copyright (c) 2026 FractalLock. Use of this source code is governed by the FractalLock Core License found in the LICENSE file.

const fs = require("fs");
const sodium = require("libsodium-wrappers");
const secrets = require("secrets.js-grempe")
const { openVault } = require("../internal/container")

const {
    parseCreateArgs,
    encryptFiles,
    buildPayload,
    buildManifest,
    encryptManifest,
    loadShares
} = require("../internal/helpers")

async function unlockVault({vaultPath, sharePaths}) {
    await sodium.ready;
    if (!vaultPath || sharePaths.length === 0) {
        console.error("Usage: recover <vault> <share1> <share2> ...")
        return
    }
    
    let vault
    try {
        vault = openVault(vaultPath)
    } catch (e) {
        console.error(e.message)
        return
    }

    const { fd, metadata, payloadStart } = vault

    const version = metadata.versions[metadata.versions.length - 1]


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

    // Cache for decrypted version keys
    const versionKeyCache = new Map()
    
    function getVersionKey(versionId) {
        if (versionKeyCache.has(versionId)) {
            return versionKeyCache.get(versionId)
        }

        const v = metadata.versions.find(v => v.id === versionId)
        if (!v) {
            throw new Error(`Missing version ${versionId}`)
        }

        const vk = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
            null,
            sodium.from_base64(v.encryptedVersionKey.ciphertext),
            null,
            sodium.from_base64(v.encryptedVersionKey.nonce),
            recoveredRootKey
        )

        versionKeyCache.set(versionId, vk)
        return vk
    }

    // Build index of all encrypted files across all versions
    const fileIndex = new Map()

    for (const v of metadata.versions) {
        for (const f of v.payload.files) {
            fileIndex.set(f.id, f)
        }
    }

    // const payloadStart = 20 + metadataLength
    // console.log(metadata.versions)
    // console.log(`Recovering version ${version.id} (${version.createdAt})`)

     //Manifest buffer info is taken from the metadata
    const manifestMeta = version.payload.manifest
    //The manifest buffer is created using the known length, then the manifest itself is extracted from the container using the known location and length
    const encryptedManifestBuf = Buffer.alloc(manifestMeta.length)
    fs.readSync(
        fd,
        encryptedManifestBuf,
        0,
        manifestMeta.length,
        payloadStart + manifestMeta.offset
    )
    //The manifest is then decrypted using the version key 
    const latestVersionKey = getVersionKey(version.id)
    let manifest
    try {
        const manifestPlain = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
            null,
            encryptedManifestBuf,
            null,
            sodium.from_base64(manifestMeta.nonce),
            latestVersionKey
        )

        manifest = JSON.parse(
            Buffer.from(manifestPlain).toString("utf8")
        )
        sodium.memzero(manifestPlain)
        sodium.memzero(encryptedManifestBuf)
    } catch {
        console.error("Failed to decrypt manifest")
        fs.closeSync(fd)
        return
    }

    const recoveredFiles = []

    //For each file in the manifest, get the metadata for that file
    for (const fileEntry of manifest.files) {
        const fileMeta = fileIndex.get(fileEntry.id)
        if (!fileMeta.versionId) {
            console.error(`Missing versionId for file ${fileEntry.name}`)
            continue
        }
        if (!fileMeta) {
            console.error(`Vault is corrupted: payload missing for ${fileEntry.name}`)
            continue
        }

        //Use the known location and length of the file to extract it from the container
        const encryptedFileBuf = Buffer.alloc(fileMeta.length)
        fs.readSync(
            fd,
            encryptedFileBuf,
            0,
            fileMeta.length,
            payloadStart + fileMeta.offset
        )
        
        //Decrypt the file using the file's version key
        let decryptedFile
        try {
            const fileVersionKey = getVersionKey(fileMeta.versionId)

            decryptedFile = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
                null,
                encryptedFileBuf,
                null,
                sodium.from_base64(fileMeta.nonce),
                fileVersionKey
            )            
        } catch {
            console.error(`Failed to decrypt ${fileEntry.name}`)
            continue
        }

        const outputName = fileEntry.name
        recoveredFiles.push(outputName)
        sodium.memzero(encryptedFileBuf)
    }

    sodium.memzero(recoveredRootKey)
    for (const vk of versionKeyCache.values()) {
        sodium.memzero(vk)
    }    
    fs.closeSync(fd)


    return {
        recoveredFiles
    }
}

module.exports = unlockVault