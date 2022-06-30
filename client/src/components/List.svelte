{#await pendingRequest}
    <p>Loading…</p>
{:then list}
    <p>Loaded</p>
    <pre>{JSON.stringify(list, null, '  ')}</pre>
{:catch err}
    <p>Error while trying to connect with the </p>
{/await}

<script lang="ts">
import {Request, ResponseNotOkError} from '../lib/request'

import {createEventDispatcher, onDestroy, onMount} from 'svelte'

const dispatch = createEventDispatcher()

let pendingRequest: Promise<pendingRequestItem[]>
let refreshInterval = 0
let redirectTimeout = 0

onMount(() => {
    // Request the list of pending items
    pendingRequest = ListPending()

    // Refresh in background every 10 seconds
    void pendingRequest.then(() => {
        refreshInterval = setInterval(ListPending, 10_000)
    })
})

onDestroy(ClearRefreshInterval)

type pendingRequestItem = {
    state: string
    operation: string
    keyId: string
    vaultName: string
    requestor: string
    date: string
    expiry: string
}

type apiListResponse = {
    pending: pendingRequestItem[]
}

async function ListPending(): Promise<pendingRequestItem[]> {
    // Once the app loads, check if we can connect to the server and have a valid session
    try {
        // Request the list
        const res = await Request<apiListResponse>('/api/list')

        // Check if the session has expired
        if (!res?.ttl || res.ttl < 1) {
            RedirectToAuth()
            return []
        }

        // When the session has expired, send a notification to the App
        if (redirectTimeout) {
            clearTimeout(redirectTimeout)
        }
        redirectTimeout = setTimeout(() => {
            ClearRefreshInterval()
            dispatch('sessionExpired', true)
        }, res.ttl * 1000)

        return res.data?.pending || []
    }
    catch (e) {
        // If the error is that we got a 401 response, redirect to the auth page
        if (e instanceof ResponseNotOkError && e.statusCode == 401) {
            RedirectToAuth()
        }
        // Re-throw any other error
        throw e
    }

    return []
}

function ClearRefreshInterval() {
    refreshInterval && clearInterval(refreshInterval)
}

function RedirectToAuth() {
    window.location.href = URL_PREFIX + '/auth'
}
</script>
