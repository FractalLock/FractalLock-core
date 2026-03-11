


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

module.exports = metadataInfo