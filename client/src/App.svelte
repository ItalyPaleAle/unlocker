{#await loadSession}
    <p>Loading…</p>
{:then _}
    <p>Loaded</p>
{:catch err}
    <p>Error while trying to connect with the </p>
{/await}

<script lang="ts">
import {Request, ResponseNotOkError} from './lib/request'

import {onDestroy, onMount} from 'svelte'

type authSessionResponse = {
    ttl: number
}

let loadSession: Promise<void>
let refreshInterval = 0
onMount(() => {
    loadSession = CheckSession()
    refreshInterval = setInterval(CheckSession, 10_000)
})
onDestroy(() => {
    clearInterval(refreshInterval)
})

function RedirectToAuth() {
    window.location.href = URL_PREFIX + '/auth'
}

let redirectTimeout = 0
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
            RedirectToAuth()
        }, res.ttl * 1000)
    }
    catch (e) {
        // If the error is that we got a 401 response, redirect to the auth page
        if (e instanceof ResponseNotOkError && e.statusCode == 401) {
            RedirectToAuth()
        }
    }
}
</script>
