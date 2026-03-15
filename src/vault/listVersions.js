const fs = require("fs")
const { openVault } = require("../internal/container")

async function listVersions(vaultPath) {
    const vault = openVault(vaultPath)
    const { metadata, fd } = vault

    const versions = metadata.versions
    .map(v => ({
        id: v.id,
        createdAt: v.createdAt,
        fileCount: v.payload.files.length
    }))
    .sort((a,b) => new Date(b.createdAt) - new Date(a.createdAt))

    fs.closeSync(fd)

    return versions
}

module.exports = listVersions