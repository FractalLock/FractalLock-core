// Copyright (c) 2026 FractalLock. Use of this source code is governed by the FractalLock Core License found in the LICENSE file.

const fs = require("fs");

function openVault(vaultPath) {
    const fd = fs.openSync(vaultPath, "r")
    const headerBuf = Buffer.alloc(20)
    fs.readSync(fd, headerBuf, 0, 20, 0)

    const magic = headerBuf.slice(0, 12).toString("ascii")
    if (magic !== "FRACTALLOCK\0") {
        console.error(`Not a valid FractalLock file: ${magic}`)
        fs.closeSync(fd)
        throw new Error("Invalid FractalLock file (bad magic header)")
    }

    const containerVersion = headerBuf.readUInt32LE(12)
    if (containerVersion !== 1) {
        console.error("Unsupported container version")
        fs.closeSync(fd)
        throw new Error(`Unsupported container version: ${containerVersion}`)
    }

    const metadataLength = headerBuf.readUInt32LE(16)

    const metadataBuf = Buffer.alloc(metadataLength)
    fs.readSync(fd, metadataBuf, 0, metadataLength, 20)

    let metadata
    try {
        metadata = JSON.parse(metadataBuf.toString("utf8"))
    } catch {
        console.error("Failed to parse metadata JSON")
        fs.closeSync(fd)
        throw new Error("Failed to parse metadata JSON")
    }

    return {
        fd,
        metadata,
        metadataLength,
        payloadStart: 20 + metadataLength
    }

}

module.exports = { openVault }