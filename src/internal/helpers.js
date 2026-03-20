// Copyright (c) 2026 FractalLock. Use of this source code is governed by the FractalLock Core License found in the LICENSE file.

const fs = require("fs");
const sodium = require("libsodium-wrappers");
const secrets = require("secrets.js-grempe")
const path = require("path");

function parseCreateArgs(args) {
    let shares = 3
    let threshold = 2
    const files = []
    
    for (let i = 0; i < args.length; i++) {
        if (args[i] === "--shares") {
        shares = parseInt(args[++i], 10)
        } else if (args[i] === "--threshold") {
        threshold = parseInt(args[++i], 10)
        } else {
        files.push(args[i])
        }
    }
    
    return { shares, threshold, files }
}

function encryptFiles(files, versionKey) {
    console.log(files)
    console.log(versionKey)
    const encryptedFiles = []
    for (const file of files) {
        console.log(file);
        const name = file.name ? file.name : path.basename(file.path)
        const fileId = sodium.to_hex(sodium.randombytes_buf(4))
        const fileNonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_IETF_NPUBBYTES)
        const fileCipher = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
            file.data,
            null,
            null,
            fileNonce,
            versionKey
        )
        encryptedFiles.push({
            id: fileId,
            originalName: name,
            size: file.data.length,
            nonce: fileNonce,
            ciphertext: fileCipher
        })
    }
    return encryptedFiles
}

function buildPayload(encryptedFiles, manifestCipher) {
    const payloadChunks = []
    let currentOffset = 0
  
    // append encrypted files
    for (const f of encryptedFiles) {
        payloadChunks.push(Buffer.from(f.ciphertext))
        f.offset = currentOffset
        f.length = f.ciphertext.length
        currentOffset += f.length
    }
  
    // append encrypted manifest
    payloadChunks.push(Buffer.from(manifestCipher))
    const manifestOffset = currentOffset
    const manifestLength = manifestCipher.length
    currentOffset += manifestLength

    const payloadBuffer = Buffer.concat(payloadChunks)
  
    return {
        payloadBuffer,
        manifestMeta: {
            offset: manifestOffset,
            length: manifestLength
        }
    }
}

function buildManifest(encryptedFiles) {
    return {
        files: encryptedFiles.map(f => ({
            id: f.id,
            name: f.originalName
        }))
    }
}

function encryptManifest(manifest, versionKey) {
    const manifestBytes = Buffer.from(JSON.stringify(manifest), "utf8")
    const manifestNonce = sodium.randombytes_buf(
        sodium.crypto_aead_xchacha20poly1305_IETF_NPUBBYTES
    )
    const manifestCipher = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        manifestBytes,
        null,
        null,
        manifestNonce,
        versionKey
    )
    sodium.memzero(manifestBytes)

    return {
        cipher: manifestCipher,
        nonce: manifestNonce
    }
}

function loadShares(sharePaths, threshold) {
    if (sharePaths.length < threshold) {
      throw new Error(
        `Need at least ${threshold} keyShares, got ${sharePaths.length}`
      )
    }
  
    return sharePaths.map(p =>
      fs.readFileSync(p, "utf8").trim()
    )
}

module.exports = {
    parseCreateArgs,
    encryptFiles,
    buildPayload,
    buildManifest,
    encryptManifest,
    loadShares
}
