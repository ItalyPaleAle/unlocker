<h1 class="text-lg font-medium text-slate-900 dark:text-white">Pending requests</h1>

{#if pageError}
    <p>Error while requesting the list of pending items: {pageError}</p>
{/if}
{#if list === null}
    <div class="px-8 py-8 mx-auto my-4 text-lg text-center bg-white rounded-lg shadow-lg lg:text-left lg:pl-20 dark:bg-slate-800 ring-1 ring-slate-900/5 text-slate-700 dark:text-slate-200">
        <LoadingSpinner size="3rem" /> Loading…
    </div>
{:else}
    <div class="space-y-4">
        {#each Object.entries(list) as [state, item] (state)}
            <div class="px-4 py-2 mx-auto my-4 bg-white rounded-lg shadow-lg dark:bg-slate-800 ring-1 ring-slate-900/5 text-slate-700 dark:text-slate-200">
                <PendingItem {item} />
            </div>
        {:else}
            <p>There's no request pending your action at this time.</p>
            <p class="text-sm">Need help getting started? Check out the <a href="https://github.com/italypaleale/unlocker#apis" class="underline hover:text-slate-900 hover:dark:text-white">documentation</a> for the APIs.</p>
        {/each}
    </div>
{/if}

<script lang="ts">
import LoadingSpinner from './LoadingSpinner.svelte'
import PendingItem from './PendingItem.svelte'

import {ThrowResponseNotOk, URLPrefix} from '../lib/request'
import {pendingRequestStatus, type pendingRequestItem} from '../lib/types'
import ndjson from '../lib/ndjson'

import {createEventDispatcher, onDestroy, onMount} from 'svelte'

const dispatch = createEventDispatcher()

let list: Record<string, pendingRequestItem>|null = null
let pageError: string|null = null
let redirectTimeout = 0

let stop: (() => void) | null
onMount(() => {
    // Subscribe to the list of pending items
    stop = Subscribe()
})

onDestroy(() => {
    if (stop) {
        stop()
        stop = null
    }
})

// Subscribe to the stream of pending states
// Returns a function that stops the stream
function Subscribe(): () => void {
    let controller: AbortController | null = null

    const stop = () => {
        controller && controller.abort()
        controller = null
    }

    // Start the subscription in background
    void (async () => {
        try {
            while (!controller || !controller.signal.aborted) {
                controller = new AbortController()

                // We can't use the higher-level Request API here because we need to get access to the stream
                const res = await fetch(URLPrefix + '/api/list', {
                    headers: new Headers({
                        accept: 'application/x-ndjson '
                    }),
                    credentials: 'same-origin',
                    cache: 'no-store',
                    signal: controller.signal
                })
                if (!res.ok) {
                    // If the error is that we got a 401 response, redirect to the auth page
                    if (res.status == 401) {
                        RedirectToAuth()
                        return
                    }
                    await ThrowResponseNotOk(res)
                }

                // Check if the session has expired
                let ttl = 0
                const ttlHeader = res.headers.get('x-session-ttl')
                if (ttlHeader) {
                    ttl = parseInt(ttlHeader, 10)
                    if (ttl < 1) {
                        ttl = 0
                    }
                }
                if (ttl < 2) {
                    stop()
                    RedirectToAuth()
                    return
                }

                // When the session has expired, send a notification to the App
                if (redirectTimeout) {
                    clearTimeout(redirectTimeout)
                }
                // Send the signal 1 second earlier so this is triggered before the server closes the request
                // If the server gets to this before the client, the loop is restarted and the client is redirected (see above where we check for 401 responses) rather than seeing a message here
                redirectTimeout = setTimeout(() => {
                    stop()
                    dispatch('sessionExpired', true)
                }, (ttl - 1) * 1000)

                // Get the stream of NDJSON messages
                if (!res.body) {
                    throw Error('Response does not contain any body')
                }

                // We have a stream now so we can initialize the list
                if (list === null) {
                    list = {}
                }

                const gen = ndjson<pendingRequestItem>(res.body.getReader())
                while (true) { // eslint-disable-line no-constant-condition
                    const {done, value} = await gen.next()
                    console.log(done, value)
                    // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
                    if (done) {
                        break
                    }
                    if (value) {
                        UpdateList(value)
                    }
                }
            }
        } catch (err) {
            // eslint-disable-next-line @typescript-eslint/restrict-plus-operands
            pageError = 'Error: ' + err
            stop()
        }
    })()

    return stop
}

function UpdateList(el: pendingRequestItem) {
    if (!el?.state || !list) {
        return
    }

    // Set or update the element in the list
    if (!list[el.state]?.status) {
        list[el.state] = el
    } else if (list[el.state].status == pendingRequestStatus.pendingRequestPending) {
        list[el.state].status = el.status
    }

    // Force a refresh
    list = list
}

function RedirectToAuth() {
    window.location.href = URLPrefix + '/auth'
}
</script>
