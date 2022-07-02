{#if title}
    <svg xmlns="http://www.w3.org/2000/svg"
        class="w-{size} h-{size}"
        viewBox="0 0 24 24"
        fill="none" stroke="currentColor" stroke-width="2"
        role="img" aria-label="{title}"
    >
        <title>{title}</title>
        <slot />
    </svg>
{:else}
    <svg xmlns="http://www.w3.org/2000/svg"
        class="w-{size} h-{size}"
        viewBox="0 0 24 24"
        fill="none" stroke="currentColor" stroke-width="2"
        aria-hidden="true"
    >
        <slot />
    </svg>
{/if}

<script lang="ts">
export let title: string
export let size: string
</script>