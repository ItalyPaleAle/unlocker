export type pendingRequestItem = {
    state: string
    operation: string
    keyId: string
    vaultName: string
    requestor: string
    date: string
    expiry: string
}

export type apiListResponse = {
    pending: pendingRequestItem[]
}
