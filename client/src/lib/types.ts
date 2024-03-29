export enum pendingRequestStatus {
    // Request is still pending
    pendingRequestPending = 'pending',
    // Request has been confirmed by this client
    pendingRequestConfirmed = 'confirmed',
    // Request has been canceled by this client
    pendingRequestCanceled = 'canceled',
    // Request has been removed by the server (incl. expired requests)
    pendingRequestRemoved = 'removed',
    // Request is being processed
    // (Used in the client only)
    pendingRequestProcessing_Client = '_client_processing',
    // Request failed
    // (Used in the client only)
    pendingRequestFailed_Client = '_client_failed',
}

export interface pendingRequestItem {
    state: string
    status: pendingRequestStatus
    operation: string
    keyId: string
    vaultName: string
    requestor: string
    date: number
    expiry: number
    note?: string
}

export type apiListResponse = pendingRequestItem[]
