{#if submitting}
    {#await submitting}
        <p>Submitting...</p>
    {:then}
        <p>Done!</p>
    {/await}
{:else}
    {#if error}
        <p>Error: {error}</p>
    {/if}
    <p>
        Request to <b>{item.operation}</b> a key, using the key <b>{item.keyId}</b> from the Azure Key Vault <b>{item.vaultName}</b>. Submitted by <b>{item.requestor}</b> on <b>{item.date}</b>.
    </p>
    <div id="prompt">
        <button on:click={() => submit(true)}>Confirm</button>
        <button on:click={() => submit(false)}>Cancel</button>
    </div>
{/if}

<script lang="ts">
import {Request} from '../lib/request'
import type {pendingRequestItem} from '../lib/types'

export let item: pendingRequestItem

let submitting: Promise<void>|null = null
let error: string|null = null
function submit(confirm: boolean) {
    // Request body
    const body: {
        state: string
        confirm?: boolean
        cancel?: boolean
    } = {
        state: item.state
    }
    if (confirm) {
        body.confirm = true
    } else {
        body.cancel = true
    }

    submitting = Promise.resolve()
        .then(() => Request<{done: boolean}>('/api/confirm', {
            postData: body,
            // Set timeout to 60s as this operation can take longer
            timeout: 40_000
        }))
        .then((res) => {
            if (res?.data?.done !== true) {
                throw Error('The operation was not confirmed')
            }
        })
        .catch((err) => {
            // eslint-disable-next-line
            error = (err && typeof err.toString == 'function') ? err.toString() : ''
        })
}
</script>