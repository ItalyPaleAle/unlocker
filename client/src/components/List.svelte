{#if pendingRequest}
    {#await pendingRequest}
        <p>Loading…</p>
    {:then list}
        <p>Loaded</p>
        <pre>{JSON.stringify(list, null, '  ')}</pre>
        {#each list as item (item.state)}
            <PendingItem {item} />
        {/each}
    {:catch err}
        <p>Error while requesting the list of pending items: {err}</p>
    {/await}
{/if}

<script lang="ts">
import PendingItem from './PendingItem.svelte'

import {Request, ResponseNotOkError, URLPrefix, type Response as RequestResponse} from '../lib/request'
import type {pendingRequestItem, apiListResponse} from '../lib/types'

import {createEventDispatcher, onDestroy, onMount} from 'svelte'

const dispatch = createEventDispatcher()

let pendingRequest: Promise<pendingRequestItem[]>|null = null
let refreshInterval = 0
let redirectTimeout = 0

onMount(() => {
    // Request the list of pending items
    pendingRequest = ListPending()

    // Refresh in background every 5 seconds
    void pendingRequest.then(() => {
        refreshInterval = setInterval(() => {
            pendingRequest = ListPending()
        }, 5_000)
    })
})

onDestroy(ClearRefreshInterval)

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

    if (!res.data?.pending?.length) {
        return []
    }

    // Filter empty values
    return res.data.pending.filter((v) => v && v.state)
}

function ClearRefreshInterval() {
    refreshInterval && clearInterval(refreshInterval)
}

function RedirectToAuth() {
    window.location.href = URLPrefix + '/auth'
}
</script>
