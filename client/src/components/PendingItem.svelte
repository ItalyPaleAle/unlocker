<div class="m-2">
    {#if error}
        <p>Error: {error}</p>
    {/if}
    <p>
        Request to <b>{item.operation}</b> a key, using the key <b>{item.keyId}</b> from the Azure Key Vault <b>{item.vaultName}</b>. Submitted by <b>{item.requestor}</b> on <b>{item.date}</b>.
    </p>
    {#await submitting}
        <p>Submitting...</p>
    {:then _}
        {#if item._status === pendingRequestStatus.pendingRequestRemoved}
            <p>This request has already been completed or has expired</p>
        {:else if item._status === pendingRequestStatus.pendingRequestConfirmed}
            <p>Request confirmed</p>
        {:else if item._status === pendingRequestStatus.pendingRequestCanceled}
            <p>Request canceled</p>
        {:else}
            <div id="prompt">
                <button on:click={() => submit(true)}>Confirm</button>
                <button on:click={() => submit(false)}>Cancel</button>
            </div>
        {/if}
    {/await}
</div>

<script lang="ts">
import {Request} from '../lib/request'
import {pendingRequestStatus, type pendingRequestItem} from '../lib/types'

export let item: pendingRequestItem

let submitting: Promise<void> = Promise.resolve()
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
        .then(() => Request<{confirmed?: boolean, canceled?: boolean}>('/api/confirm', {
            postData: body,
            // Set timeout to 60s as this operation can take longer
            timeout: 60000
        }))
        .then((res) => {
            if (confirm) {
                if (res?.data?.confirmed !== true) {
                    throw Error('The operation was not confirmed')
                }
                item._status = pendingRequestStatus.pendingRequestConfirmed
            } else {
                if (res?.data?.canceled !== true) {
                    throw Error('The operation was not canceled')
                }
                item._status = pendingRequestStatus.pendingRequestCanceled
            }
            item = item
        })
        .catch((err) => {
            // eslint-disable-next-line
            error = (err && typeof err.toString == 'function') ? err.toString() : ''
        })
}
</script>