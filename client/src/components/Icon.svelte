<i class="w-{size}">
    {#if icon == 'lock-open'}
        <!--
            heroicons.com
            Copyright (c) 2020 Refactoring UI Inc
            Licensed under MIT license: https://github.com/tailwindlabs/heroicons/blob/master/LICENSE
        -->
        <IconContainer {title} {size}>
            <path stroke-linecap="round" stroke-linejoin="round" d="M8 11V7a4 4 0 118 0m-4 8v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2z" />
        </IconContainer>
    {:else if icon == 'lock-closed'}
        <!--
            heroicons.com
            Copyright (c) 2020 Refactoring UI Inc
            Licensed under MIT license: https://github.com/tailwindlabs/heroicons/blob/master/LICENSE
        -->
        <IconContainer {title} {size}>
            <path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
        </IconContainer>
    {:else if icon == 'key'}
        <!--
            heroicons.com
            Copyright (c) 2020 Refactoring UI Inc
            Licensed under MIT license: https://github.com/tailwindlabs/heroicons/blob/master/LICENSE
        -->
        <IconContainer {title} {size}>
            <path stroke-linecap="round" stroke-linejoin="round" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
        </IconContainer>
    {:else if icon == 'clock'}
        <!--
            heroicons.com
            Copyright (c) 2020 Refactoring UI Inc
            Licensed under MIT license: https://github.com/tailwindlabs/heroicons/blob/master/LICENSE
        -->
        <IconContainer {title} {size}>
            <path stroke-linecap="round" stroke-linejoin="round" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
        </IconContainer>
    {:else if icon == 'note'}
        <!--
            heroicons.com
            Copyright (c) 2020 Refactoring UI Inc
            Licensed under MIT license: https://github.com/tailwindlabs/heroicons/blob/master/LICENSE
        -->
        <IconContainer {title} {size}>
            <path stroke-linecap="round" stroke-linejoin="round" d="M7.5 8.25h9m-9 3H12m-9.75 1.51c0 1.6 1.123 2.994 2.707 3.227 1.129.166 2.27.293 3.423.379.35.026.67.21.865.501L12 21l2.755-4.133a1.14 1.14 0 01.865-.501 48.172 48.172 0 003.423-.379c1.584-.233 2.707-1.626 2.707-3.228V6.741c0-1.602-1.123-2.995-2.707-3.228A48.394 48.394 0 0012 3c-2.392 0-4.744.175-7.043.513C3.373 3.746 2.25 5.14 2.25 6.741v6.018z" />
        </IconContainer>
    {:else if icon == 'check-circle'}
        <!--
            heroicons.com
            Copyright (c) 2020 Refactoring UI Inc
            Licensed under MIT license: https://github.com/tailwindlabs/heroicons/blob/master/LICENSE
        -->
        <IconContainer {title} {size}>
            <path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
        </IconContainer>
    {:else if icon == 'x-circle'}
        <!--
            heroicons.com
            Copyright (c) 2020 Refactoring UI Inc
            Licensed under MIT license: https://github.com/tailwindlabs/heroicons/blob/master/LICENSE
        -->
        <IconContainer {title} {size}>
            <path stroke-linecap="round" stroke-linejoin="round" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
        </IconContainer>
    {:else if icon == 'data'}
        <!--
            heroicons.com
            Copyright (c) 2020 Refactoring UI Inc
            Licensed under MIT license: https://github.com/tailwindlabs/heroicons/blob/master/LICENSE
        -->
        <IconContainer {title} {size}>
            <path stroke-linecap="round" stroke-linejoin="round" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4" />
        </IconContainer>
    {/if}
</i>

<script lang="ts">
import IconContainer from './IconContainer.svelte'

export let icon: string
export let title: string
export let size = '12'
</script>