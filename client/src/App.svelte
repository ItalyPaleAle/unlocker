{#if sessionExpired}
    <p>Your session has expired.</p>
    <button on:click={() => window.location.reload()}>Reload page</button>
{:else}
    <List on:sessionExpired={setSessionExpired}/>
{/if}

<script lang="ts">
import List from './components/List.svelte'

let sessionExpired = false

function setSessionExpired(event: CustomEvent<boolean>) {
    sessionExpired = event.detail
}
</script>
