
const sodium = require("libsodium-wrappers");
const { openVault } = require("../internal/container")

async function metadataInfo(vaultPath) {
    await sodium.ready;
    if (!vaultPath) {
        throw new Error("Vault path not provided")
        return
    }
    
    let vault
    try {
        vault = openVault(vaultPath)
    } catch (e) {
        throw new Error(`Failed to open vault: ${e.message}`)
    }
    
    const { metadata } = vault

    return metadata
}

module.exports = metadataInfo