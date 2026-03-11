const fs = require("fs");

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

module.exports = { openVault }