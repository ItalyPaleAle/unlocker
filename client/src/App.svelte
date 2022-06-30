{#if sessionExpired}
    <p>Your session has expired.</p>
    <button on:click={() => window.location.reload()}>Reload</button>
{:else}
    {#await loadSession}
        <p>Loading…</p>
    {:then _}
        <p>Loaded</p>
    {:catch err}
        <p>Error while trying to connect with the </p>
    {/await}
{/if}

<script lang="ts">
import {Request, ResponseNotOkError} from './lib/request'

import {onDestroy, onMount} from 'svelte'

let loadSession: Promise<void>
let refreshInterval = 0
let redirectTimeout = 0
let sessionExpired = false

onMount(() => {
    loadSession = CheckSession()
    void loadSession.then(() => {
        refreshInterval = setInterval(CheckSession, 10_000)
    })
})

onDestroy(ClearRefreshInterval)

type authSessionResponse = {
    ttl: number
}

async function CheckSession() {
    // Once the app loads, check if we can connect to the server and have a valid session
    try {
        // Get the remaining TTL
        const res = await Request<authSessionResponse>('/auth/session')
        if (typeof res?.ttl != 'number' || res.ttl < 1) {
            RedirectToAuth()
            return
        }

        // Set up a page reload for when the session has expired
        if (redirectTimeout) {
            clearTimeout(redirectTimeout)
        }
        redirectTimeout = setTimeout(() => {
            ClearRefreshInterval()
            sessionExpired = true
        }, res.ttl * 1000)
    }
    catch (e) {
        // If the error is that we got a 401 response, redirect to the auth page
        if (e instanceof ResponseNotOkError && e.statusCode == 401) {
            RedirectToAuth()
        }
    }
}

function ClearRefreshInterval() {
    refreshInterval && clearInterval(refreshInterval)
}

function RedirectToAuth() {
    window.location.href = URL_PREFIX + '/auth'
}
</script>
