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
            originalName: path.basename(file.path),
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

function openVault(vaultPath) {
    const fd = fs.openSync(vaultPath, "r")
    const headerBuf = Buffer.alloc(16)
    fs.readSync(fd, headerBuf, 0, 16, 0)

    const magic = headerBuf.slice(0, 8).toString("ascii")
    if (magic !== "LOCKBOX\0") {
        console.error("Not a valid Lockbox file")
        fs.closeSync(fd)
        return
    }

    const containerVersion = headerBuf.readUInt32LE(8)
    if (containerVersion !== 1) {
        console.error("Unsupported container version")
        fs.closeSync(fd)
        return
    }

    const metadataLength = headerBuf.readUInt32LE(12)

    const metadataBuf = Buffer.alloc(metadataLength)
    fs.readSync(fd, metadataBuf, 0, metadataLength, 16)

    let metadata
    try {
        metadata = JSON.parse(metadataBuf.toString("utf8"))
    } catch {
        console.error("Failed to parse metadata JSON")
        fs.closeSync(fd)
        return
    }

    return {
        fd,
        metadata,
        metadataLength,
        payloadStart: 16 + metadataLength
    }

}


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
    
    const vaultPath = path.join(vaultDir, 'myvault.lockbox')

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
            magic: "LOCKBOX",
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

    const header = Buffer.alloc(16)
    header.write("LOCKBOX\0", 0, "ascii")
    header.writeUInt32LE(1, 8)                // container version
    header.writeUInt32LE(metadataJson.length, 12)
    
    const container = Buffer.concat([
        header,
        metadataJson,
        payloadBuffer
    ])
        
    fs.writeFileSync(vaultPath, container)
    // console.log("Vault written to myvault.lockbox")

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

async function recoverVault({vaultPath, sharePaths, requestedVersion = null, recoverPath = null}) {
    await sodium.ready;
    if (!vaultPath || sharePaths.length === 0) {
        // console.error("Usage: recover <vault> <share1> <share2> ...")
        throw new Error("No vault path and/or keyShares selected")
        return
    }

    const vaultDir = path.dirname(vaultPath)

    let vault
    try {
        vault = openVault(vaultPath)
    } catch (e) {
        console.error(e.message)
        return
    }

    const { fd, metadata, payloadStart } = vault

    let version
    if (requestedVersion !== null) {
        version = metadata.versions.find(v => v.id === requestedVersion)
        if (!version) {
            throw new Error(`Version ${requestedVersion} not found`)
        }
    } else {
        version = metadata.versions[metadata.versions.length - 1]
    }

    if (recoverPath === null) {
        recoverPath = path.join(vaultDir, "recovered")
    }

    if (recoverPath !== "outputOnly") {
        if (!fs.existsSync(recoverPath)) {
            fs.mkdirSync(recoverPath, { recursive: true })
        }
    }

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

    // const payloadStart = 16 + metadataLength
    console.log(metadata.versions)
    console.log(`Recovering version ${version.id} (${version.createdAt})`)

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
        const outputName = `recovered_${fileEntry.name}`
        let outputPath = path.join(recoverPath, outputName)
        if (recoverPath !== "outputOnly") {
            fs.writeFileSync(outputPath, decryptedFile)
        } else {
            outputPath = outputName
        }
        console.log(`Recovered ${outputName}`)
        recoveredFiles.push(outputPath)
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

async function updateVault({vaultPath, sharePaths, inputFiles}) {
    await sodium.ready;
    
    console.log(vaultPath, sharePaths, inputFiles)
    if (inputFiles.length === 0) {
        throw new Error("No input files provided")
    }
    for (const filePath of inputFiles) {
        if (!fs.existsSync(filePath)) {
            throw new Error(`Input file does not exist: ${filePath}`)
        }
    }

    if (!vaultPath || sharePaths.length === 0) {
        throw new Error("No vault path and/or keyShares selected")
    }

    const files = inputFiles.map(filePath => ({
        path: filePath,
        data: fs.readFileSync(filePath)
    }))
    
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
    const encryptedFiles = encryptFiles(files, versionKey)

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

    // Add new / updated files
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

    metadata.versions.push({
        id: metadata.versions.length + 1,
        createdAt: new Date().toISOString(),
        encryptedVersionKey: {
            nonce: sodium.to_base64(vkNonce),
            ciphertext: sodium.to_base64(encryptedVk)
        },
        payload: {
            files: encryptedFiles.map(f => ({
                id: f.id,
                versionId: metadata.versions.length + 1,
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
    })

    console.log(metadata)
        
    const metadataJson = Buffer.from(JSON.stringify(metadata), "utf8")

    const header = Buffer.alloc(16)
    header.write("LOCKBOX\0", 0, "ascii")
    header.writeUInt32LE(1, 8)
    header.writeUInt32LE(metadataJson.length, 12)

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

    // const payloadStart = 16 + metadataLength
    console.log(metadata.versions)
    console.log(`Recovering version ${version.id} (${version.createdAt})`)

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

async function metadataInfo(vaultPath) {
    await sodium.ready;
    if (!vaultPath) {
        console.error("Usage: info <vault>")
        return
    }
    
    let vault
    try {
        vault = openVault(vaultPath)
    } catch (e) {
        console.error(e.message)
        return
    }
    
    const { metadata } = vault

    return metadata
}
module.exports = { createVault, recoverVault, updateVault, deleteFromVault, unlockVault, metadataInfo }