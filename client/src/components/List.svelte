{#await pendingRequest}
    <p>Loading…</p>
{:then _}
    <p>Loaded</p>
    <pre class="text-xs">{JSON.stringify(list, null, '  ')}</pre>
    {#each Object.entries(list) as [state, item] (state)}
        <PendingItem {item} />
    {/each}
{:catch err}
    <p>Error while requesting the list of pending items: {err}</p>
{/await}

<script lang="ts">
import PendingItem from './PendingItem.svelte'

import {Request, ResponseNotOkError, URLPrefix, type Response as RequestResponse} from '../lib/request'
import {type pendingRequestItem, type apiListResponse, pendingRequestStatus} from '../lib/types'

import {createEventDispatcher, onDestroy, onMount} from 'svelte'

const dispatch = createEventDispatcher()

let list: Record<string, pendingRequestItem> = {}
// Initialize with a Promise that never resolves to start
// eslint-disable-next-line @typescript-eslint/no-empty-function
let pendingRequest: Promise<void> = new Promise(() => {})
let refreshInterval = 0
let redirectTimeout = 0

onMount(() => {
    // Request the list of pending items
    pendingRequest = RefreshList()

    // Refresh in background every 5 seconds
    void pendingRequest.then(() => {
        refreshInterval = setInterval(() => {
            // Refresh in background
            void RefreshList()
        }, 5_000)
    })
})

onDestroy(ClearRefreshInterval)

// Refreshes the values of "list"
async function RefreshList(): Promise<void> {
    // Request the list of pending items
    const res = await ListPending()
    const listKeys = Object.keys(list)
    for (let i = 0; i < res.length; i++) {
        const state = res[i].state
        // If an element already exists, remove the key from the list
        if (list[state]) {
            const idx = listKeys.indexOf(state)
            if (idx > -1) {
                listKeys.splice(idx, 1)
            }
            continue
        }
        // Add the new elements
        list[state] = res[i]
    }

    // All items that remain in listKeys are those that have been removed or completed
    for (let i = 0; i < listKeys.length; i++) {
        if (list[listKeys[i]]._status === undefined) {
            list[listKeys[i]]._status = pendingRequestStatus.pendingRequestRemoved
        }
    }

    // Force a refresh
    list = list
}

// Fetches the list of pending items from the server
// It also sets a timeout that causes sessionExpired message when the user's session has expired
async function ListPending(): Promise<pendingRequestItem[]> {
    // Once the app loads, check if we can connect to the server and have a valid session
    let res: RequestResponse<apiListResponse>
    try {
        // Request the list
        res = await Request<apiListResponse>('/api/list')
    } catch (e) {
        // If the error is that we got a 401 response, redirect to the auth page
        if (e instanceof ResponseNotOkError && e.statusCode == 401) {
            RedirectToAuth()
        }
        // Re-throw any other error
        throw e
    }

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

    if (!res.data?.length) {
        return []
    }

    // Filter empty values and return the list
    return res.data.filter((v) => v && v.state)
}

function ClearRefreshInterval() {
    refreshInterval && clearInterval(refreshInterval)
}

function RedirectToAuth() {
    window.location.href = URLPrefix + '/auth'
}
</script>
