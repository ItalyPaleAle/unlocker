<div class="my-2">
    {#if error}
        <p>Error: {error}</p>
    {/if}
    <div class="flex flex-row">
        <div class="flex-none mr-4 w-14 h-14 text-slate-700 dark:text-slate-300">
            {#if item.operation == 'wrap'}
                <Icon icon="lock-closed" title="Wrap request" size="14" />
            {:else if item.operation == 'unwrap'}
                <Icon icon="lock-open" title="Unwrap request" size="14" />
            {/if}
        </div>
        <div>
            <div>
                <span class="flex flex-row items-center">
                    <span class="flex-none w-6 pr-2"></span>
                    <span class="flex-grow">
                        <b class="text-slate-900 dark:text-white">{item.requestor}</b> wants to <b class="text-slate-900 dark:text-white">{item.operation}</b> a key
                    </span>
                </span>
                <span class="flex flex-row items-center text-sm">
                    <span class="flex-grow-0 w-6 pr-2">
                        <Icon icon="key" title="Vault name and key" size={'4'} />
                    </span>
                    <span class="flex-grow">
                        <b class="text-slate-900 dark:text-white">{item.vaultName}</b> / <b class="text-slate-900 dark:text-white">{item.keyId}</b>
                    </span>
                </span>
                <span class="flex flex-row items-center text-sm">
                    <span class="flex-grow-0 w-6 pr-2">
                        <Icon icon="clock" title="Time of the request (local)" size={'4'} />
                    </span>
                    <span class="flex-grow">
                        <b class="text-slate-900 dark:text-white">{format(item.date * 1000, 'PPpp')}</b>
                    </span>
                </span>
            </div>
            {#await submitting}
                <p>Working on it...</p>
            {:then _}
                {#if item.status === pendingRequestStatus.pendingRequestRemoved}
                    <p>This request has already been completed or has expired</p>
                {:else if item.status === pendingRequestStatus.pendingRequestConfirmed}
                    <p>Request confirmed</p>
                {:else if item.status === pendingRequestStatus.pendingRequestCanceled}
                    <p>Request canceled</p>
                {:else if item.status === pendingRequestStatus.pendingRequestProcessing_Client}
                    <p>Working on it...</p>
                {:else}
                    <div class="flex flex-row">
                        <div role="button"
                            class="flex flex-row items-center flex-auto p-2 m-2 rounded shadow-sm text-emerald-700 dark:text-emerald-400 hover:text-slate-900 hover:dark:text-white bg-slate-200 dark:bg-slate-700 border-emerald-300 dark:border-emerald-600 hover:bg-emerald-300 hover:dark:bg-emerald-600"
                            on:click={() => submit(true)}
                        >
                            <span class="pr-2 w-7">
                                <Icon icon="check-circle" title="" size={'5'} /> 
                            </span>
                            <span>Confirm</span>
                        </div>
                        <div role="button"
                            class="flex flex-row items-center flex-auto p-2 m-2 rounded shadow-sm text-rose-700 dark:text-rose-400 hover:text-slate-900 hover:dark:text-white bg-slate-200 dark:bg-slate-700 border-rose-300 dark:border-rose-600 hover:bg-rose-300 hover:dark:bg-rose-600"
                            on:click={() => submit(false)}
                        >
                            <span class="pr-2 w-7">
                                <Icon icon="x-circle" title="" size={'5'} /> 
                            </span>
                            <span>Cancel</span>
                        </div>
                    </div>
                {/if}
            {/await}
        </div>
    </div>
</div>

<script lang="ts">
import {format} from 'date-fns'

import {Request} from '../lib/request'
import {pendingRequestStatus, type pendingRequestItem} from '../lib/types'

import Icon from './Icon.svelte'

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

    // Make the request as processing in the client, so its status won't be changed to "removed" by the server
    item.status = pendingRequestStatus.pendingRequestProcessing_Client

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
                item.status = pendingRequestStatus.pendingRequestConfirmed
            } else {
                if (res?.data?.canceled !== true) {
                    throw Error('The operation was not canceled')
                }
                item.status = pendingRequestStatus.pendingRequestCanceled
            }
            item = item
        })
        .catch((err) => {
            // eslint-disable-next-line
            error = (err && typeof err.toString == 'function') ? err.toString() : ''
        })
}
</script>