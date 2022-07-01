export enum pendingRequestStatus {
    // Request is still pending
    pendingRequestPending = -1,
    // Request has been removed by the server (incl. expired requests)
    pendingRequestRemoved,
    // Request has been confirmed by this client
    pendingRequestConfirmed,
    // Request has been canceled by this client
    pendingRequestCanceled,
}

export type pendingRequestItem = {
    state: string
    operation: string
    keyId: string
    vaultName: string
    requestor: string
    date: number
    expiry: number

    // Added by our code
    _status?: pendingRequestStatus
}

export type apiListResponse = pendingRequestItem[]
