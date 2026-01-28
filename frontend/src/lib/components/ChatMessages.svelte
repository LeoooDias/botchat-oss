<!--
============================================================================
⚠️  PUBLIC FILE - Part of botchat-oss transparency repo
============================================================================
This file is publicly visible at: https://github.com/LeoooDias/botchat-oss

Purpose: Demonstrate localStorage-only message storage (no server persistence)

⚠️  DO NOT add proprietary business logic here
⚠️  Only message handling transparency code belongs in this file
============================================================================
-->

<script lang="ts">
	import { createEventDispatcher, onMount } from 'svelte';
	// @ts-ignore - module resolved via parent project symlink
	import { Marked } from 'marked';
	// @ts-ignore - module resolved via parent project symlink
	import hljs from 'highlight.js';
	// @ts-ignore - module resolved via parent project symlink
	import DOMPurify from 'dompurify';
	// @ts-ignore - module resolved via parent project symlink
	import CitationsPopup from './CitationsPopup.svelte';
	// @ts-ignore - module resolved via parent project symlink
	import type { Citation } from './CitationsPopup.svelte';
	// @ts-ignore - module resolved via parent project symlink
	import { formatProviderName } from '$lib/utils/format';

	const dispatch = createEventDispatcher<{
		reply: { messageId: string; botId: string };
		export: { message: Message };
	}>();

	// Track which message is showing "Copied!" tooltip
	let copiedMessageId: string | null = null;

	async function copyMessageToClipboard(msg: Message) {
		try {
			await navigator.clipboard.writeText(msg.content);
			copiedMessageId = msg.id;
			setTimeout(() => {
				copiedMessageId = null;
			}, 1500);
		} catch (err) {
			console.error('Failed to copy message:', err);
		}
	}

	interface Message {
		id: string;
		role: 'user' | 'assistant';
		content: string;
		timestamp: number;
		botId?: string;
		botName?: string; // Persisted bot name for display after refresh
		provider?: string;
		model?: string;
		mode?: 'chat' | 'ask' | 'study'; // v3.0.0: Mode used for this response
		isError?: boolean;
		isTruncated?: boolean; // Response was cut off due to max_tokens limit
		finishReason?: string; // Raw finish_reason from provider
		citations?: Citation[]; // Web search citations
		lastInputs?: {
			message: string;
			attachments: File[];
		};
	}

	interface Bot {
		id: string;
		provider: string;
		model?: string;
		name?: string;
		webSearchEnabled?: boolean;
	}

	export let messages: Message[] = [];
	export let activeBots: Bot[] = [];
	export let pendingBots: Set<string> = new Set(); // Bots waiting for first token (show loading spinner)
	export let onRetry: ((msg: Message) => void) | null = null;

	let messagesContainer: HTMLDivElement;
	let showCitationsPopup = false;
	let selectedCitations: Citation[] = [];

	// Create a custom marked instance with syntax highlighting
	const marked = new Marked({
		breaks: true,
		gfm: true,
		renderer: {
			link(href: string, title: string | null, text: string) {
				const titleAttr = title ? ` title="${title}"` : '';
				return `<a href="${href}"${titleAttr} target="_blank" rel="noopener noreferrer">${text}</a>`;
			},
			code(code: string, language: string | undefined) {
				const lang = language || '';
				const displayLang = lang || 'text';
				const validLang = hljs.getLanguage(lang) ? lang : 'plaintext';
				const highlighted = hljs.highlight(code, { language: validLang }).value;
				
				// Escape the code for the data attribute (for copy functionality)
				const escapedCode = code.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
				
				return `<div class="code-block-wrapper">
	<div class="code-block-header">
		<span class="code-lang">${displayLang}</span>
		<button class="copy-btn" data-code="${escapedCode}" title="Copy code">
			<svg class="copy-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
				<rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
				<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
			</svg>
			<svg class="check-icon hidden" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
				<polyline points="20 6 9 17 4 12"></polyline>
			</svg>
			<span class="copy-text">Copy</span>
		</button>
	</div>
	<pre><code class="hljs language-${validLang}">${highlighted}</code></pre>
</div>`;
			}
		}
	});

	// Handle copy button clicks via event delegation
	onMount(() => {
		const handleCopyClick = async (e: Event) => {
			const target = e.target as HTMLElement;
			const copyBtn = target.closest('.copy-btn') as HTMLElement;
			if (!copyBtn) return;
			
			const code = copyBtn.dataset.code;
			if (!code) return;
			
			// Decode the escaped code
			const decodedCode = code
				.replace(/&amp;/g, '&')
				.replace(/&quot;/g, '"')
				.replace(/&lt;/g, '<')
				.replace(/&gt;/g, '>');
			
			try {
				await navigator.clipboard.writeText(decodedCode);
				
				// Show success state
				const copyIcon = copyBtn.querySelector('.copy-icon');
				const checkIcon = copyBtn.querySelector('.check-icon');
				const copyText = copyBtn.querySelector('.copy-text');
				
				copyIcon?.classList.add('hidden');
				checkIcon?.classList.remove('hidden');
				if (copyText) copyText.textContent = 'Copied!';
				
				// Reset after 2 seconds
				setTimeout(() => {
					copyIcon?.classList.remove('hidden');
					checkIcon?.classList.add('hidden');
					if (copyText) copyText.textContent = 'Copy';
				}, 2000);
			} catch (err) {
				console.error('Failed to copy:', err);
			}
		};
		
		messagesContainer?.addEventListener('click', handleCopyClick);
		return () => messagesContainer?.removeEventListener('click', handleCopyClick);
	});

	function scrollToBottom() {
		if (messagesContainer) {
			setTimeout(() => {
				messagesContainer.scrollTop = messagesContainer.scrollHeight;
			}, 0);
		}
	}

	// Track previous message count to detect new messages
	let previousMessageCount = 0;

	$: {
		// Only auto-scroll if a NEW message was added (not just updated)
		// This allows users to scroll up while tokens are streaming
		if (messages.length > previousMessageCount) {
			scrollToBottom();
			previousMessageCount = messages.length;
		} else {
			previousMessageCount = messages.length;
		}
	}

	function getBotName(msg: Message): string | null {
		if (!msg.botId) return null;
		// Prefer stored botName (immutable history) over current bot state
		// Fall back to current bot only for old messages without stored botName
		if (msg.botName) return msg.botName;
		const bot = activeBots.find((b) => b.id === msg.botId);
		return bot?.name || null;
	}

	function getBotLabel(msg: Message): string {
		if (!msg.botId) return 'Assistant';
		// Prefer stored provider (immutable history) over current bot state
		// Fall back to current bot only for old messages without stored provider
		const provider = msg.provider || activeBots.find((b) => b.id === msg.botId)?.provider;
		return provider ? formatProviderName(provider) : 'Assistant';
	}

	function getModeLabel(mode?: string): { label: string; color: string } | null {
		if (!mode) return null;
		switch (mode) {
			case 'chat': return { label: 'Chat', color: 'text-green-600 dark:text-green-400' };
			case 'ask': return { label: 'Ask', color: 'text-gray-500 dark:text-gray-400' };
			case 'study': return { label: 'Study', color: 'text-brand' };
			default: return null;
		}
	}

	function openCitations(citations: Citation[]) {
		selectedCitations = citations;
		showCitationsPopup = true;
	}

	function closeCitations() {
		showCitationsPopup = false;
		selectedCitations = [];
	}

	/**
	 * Render markdown content and sanitize HTML output to prevent XSS attacks.
	 * DOMPurify removes any potentially malicious scripts/attributes.
	 * We allow span tags with class attributes for syntax highlighting.
	 */
	function renderMarkdown(content: string): Promise<string> {
		const rawHtml = marked.parse(content);
		return Promise.resolve(DOMPurify.sanitize(rawHtml as string, {
			ADD_TAGS: ['span'],
			ADD_ATTR: ['class', 'data-code'],
			ALLOWED_TAGS: [
				'p', 'br', 'strong', 'em', 'b', 'i', 'u', 's', 'del',
				'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
				'ul', 'ol', 'li',
				'pre', 'code', 'span',
				'blockquote',
				'a',
				'div', 'button', 'svg', 'path', 'rect', 'polyline',
				'table', 'thead', 'tbody', 'tr', 'th', 'td',
				'hr'
			],
			ALLOWED_ATTR: [
				'href', 'target', 'rel', 'title',
				'class',
				'data-code',
				'width', 'height', 'viewBox', 'fill', 'stroke', 'stroke-width',
				'd', 'x', 'y', 'rx', 'ry', 'points'
			]
		}));
	}

	$: {
		// Only auto-scroll if a NEW message was added (not just updated)
		// This allows users to scroll up while tokens are streaming
		if (messages.length > previousMessageCount) {
			scrollToBottom();
			previousMessageCount = messages.length;
		} else {
			previousMessageCount = messages.length;
		}
	}
</script>

<div bind:this={messagesContainer} class="flex-1 overflow-y-auto p-3 md:p-4 space-y-3 md:space-y-4 mobile-scroll">
	{#if messages.length === 0}
		<div class="h-full flex items-center justify-center text-center px-4">
			<div>
				<svg class="w-12 h-12 mx-auto mb-3 text-gray-400 dark:text-gray-500" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" d="M20.25 8.511c.884.284 1.5 1.128 1.5 2.097v4.286c0 1.136-.847 2.1-1.98 2.193-.34.027-.68.052-1.02.072v3.091l-3-3c-1.354 0-2.694-.055-4.02-.163a2.115 2.115 0 01-.825-.242m9.345-8.334a2.126 2.126 0 00-.476-.095 48.64 48.64 0 00-8.048 0c-1.131.094-1.976 1.057-1.976 2.192v4.286c0 .837.46 1.58 1.155 1.951m9.345-8.334V6.637c0-1.621-1.152-3.026-2.76-3.235A48.455 48.455 0 0011.25 3c-2.115 0-4.198.137-6.24.402-1.608.209-2.76 1.614-2.76 3.235v6.226c0 1.621 1.152 3.026 2.76 3.235.577.075 1.157.14 1.74.194V21l4.155-4.155" />
				</svg>
				<p class="text-gray-500 dark:text-gray-400 text-base md:text-lg font-medium">No messages yet</p>
				<p class="text-gray-400 dark:text-gray-500 text-sm mt-1">Select bots and send a message to get started</p>
			</div>
		</div>
	{/if}
	
	{#each messages as msg (msg.id)}
		<div class={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
			<div class="relative max-w-[90%] md:max-w-2xl group">
				<div
					class={`px-3 md:px-4 py-2.5 md:py-3 rounded-2xl md:rounded-lg ${
						msg.role === 'user'
							? 'bg-brand text-white rounded-br-sm md:rounded-br-none'
							: msg.isError
								? 'bg-red-50 dark:bg-red-900/30 border border-red-300 dark:border-red-700 rounded-bl-sm md:rounded-bl-none text-red-900 dark:text-red-100'
								: 'bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-bl-sm md:rounded-bl-none text-gray-900 dark:text-gray-100'
					}`}
				>
					{#if msg.role === 'assistant'}
						{#if getBotName(msg)}
							<div class="text-xs font-semibold text-gray-700 dark:text-gray-300 mb-0.5">{getBotName(msg)}</div>
						{/if}
						<div class="flex items-center gap-2 mb-1.5 md:mb-2">
							<span class="text-[10px] md:text-xs font-semibold text-gray-600 dark:text-gray-400">{getBotLabel(msg)}</span>
							{#if getModeLabel(msg.mode)}
								{@const modeInfo = getModeLabel(msg.mode)}
								<span class="text-[9px] md:text-[10px] font-medium {modeInfo?.color}">• {modeInfo?.label}</span>
							{/if}
						</div>
						<div class="prose prose-sm max-w-none dark:prose-invert text-sm leading-relaxed prose-p:m-0 prose-p:mb-2 prose-headings:mt-3 prose-headings:mb-2 prose-h1:text-base prose-h2:text-sm prose-h3:text-sm prose-ul:m-0 prose-ul:mb-2 prose-ul:pl-4 prose-li:m-0 prose-ol:m-0 prose-ol:mb-2 prose-ol:pl-6 prose-blockquote:border-l-4 prose-blockquote:border-gray-400 dark:prose-blockquote:border-gray-500 prose-blockquote:pl-3 prose-blockquote:italic prose-blockquote:m-0 prose-blockquote:mb-2 prose-code:bg-gray-200 dark:prose-code:bg-gray-700 prose-code:px-1.5 prose-code:py-0.5 prose-code:rounded prose-code:text-gray-800 dark:prose-code:text-gray-300 prose-code:text-xs prose-a:text-gray-700 dark:prose-a:text-gray-300 prose-a:underline hover:prose-a:text-gray-900 dark:hover:prose-a:text-gray-100 prose-strong:font-bold prose-em:italic">
							{#await renderMarkdown(msg.content)}
								<p>Loading...</p>
							{:then html}
								{@html html}
							{:catch}
								<p>{msg.content}</p>
							{/await}
						</div>
						{#if msg.isTruncated}
							<div class="mt-2 pt-2 border-t border-amber-300 dark:border-amber-600">
								<div class="flex items-center gap-1.5 text-xs text-amber-700 dark:text-amber-400">
									<svg class="w-4 h-4 text-amber-500 flex-shrink-0" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24">
										<path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
									</svg>
									<span class="font-medium">Response truncated</span>
									<span class="text-amber-600 dark:text-amber-500">— max_tokens limit reached. Increase in bot settings for longer responses.</span>
								</div>
							</div>
						{/if}
						{#if msg.citations && msg.citations.length > 0}
							<div class="mt-2 pt-2 border-t border-gray-200 dark:border-gray-600">
								<button
									on:click={() => openCitations(msg.citations || [])}
									class="flex items-center gap-1.5 text-xs text-brand dark:text-brand-text hover:text-brand-dark dark:hover:brightness-110 transition font-medium"
								>
									<svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24">
										<path stroke-linecap="round" stroke-linejoin="round" d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-1.605.42-3.113 1.157-4.418" />
									</svg>
									<span>View {msg.citations.length} web source{msg.citations.length === 1 ? '' : 's'}</span>
									<svg class="w-3 h-3" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
										<path stroke-linecap="round" stroke-linejoin="round" d="M8.25 4.5l7.5 7.5-7.5 7.5" />
									</svg>
								</button>
							</div>
						{/if}
					{:else}
						<p class="text-sm leading-relaxed whitespace-pre-wrap">{msg.content}</p>
					{/if}
				</div>
				
				{#if msg.role === 'assistant' && msg.isError && onRetry}
					<div class="absolute -top-2 -right-2">
						<button
							class="w-5 h-5 rounded-full bg-amber-500 hover:bg-amber-600 flex items-center justify-center text-sm shadow-lg hover:shadow-xl transition-all cursor-pointer text-white text-xs leading-none pb-0.5"
							on:click={() => onRetry?.(msg)}
							title="Retry this message"
						>
							↻
						</button>
					</div>
				{/if}

		<!-- Action buttons for bot messages (not error messages) -->
		{#if msg.role === 'assistant' && !msg.isError && msg.botId}
			<!-- Export button -->
			<button
				on:click={() => dispatch('export', { message: msg })}
				class="absolute -bottom-2 right-[4.5rem] w-6 h-6 rounded-full bg-gray-100 dark:bg-gray-700 border border-gray-300 dark:border-gray-600 flex items-center justify-center hover:bg-gray-200 dark:hover:bg-gray-600 hover:border-gray-400 dark:hover:border-gray-500 transition shadow-sm opacity-0 group-hover:opacity-100 focus:opacity-100"
				title="Export this message"
			>
				<svg class="w-3.5 h-3.5 text-gray-500 dark:text-gray-400" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" />
				</svg>
			</button>
			<!-- Reply button -->
			<button
				on:click={() => dispatch('reply', { messageId: msg.id, botId: msg.botId || '' })}
				class="absolute -bottom-2 right-10 w-6 h-6 rounded-full bg-gray-100 dark:bg-gray-700 border border-gray-300 dark:border-gray-600 flex items-center justify-center hover:bg-gray-200 dark:hover:bg-gray-600 hover:border-gray-400 dark:hover:border-gray-500 transition shadow-sm opacity-0 group-hover:opacity-100 focus:opacity-100"
				title="Reply to this bot only"
			>
				<svg class="w-3.5 h-3.5 text-gray-500 dark:text-gray-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" d="M9 15L3 9m0 0l6-6M3 9h12a6 6 0 010 12h-3" />
				</svg>
			</button>
			<!-- Copy button -->
			<button
				on:click={() => copyMessageToClipboard(msg)}
				class="absolute -bottom-2 right-2 w-6 h-6 rounded-full bg-gray-100 dark:bg-gray-700 border border-gray-300 dark:border-gray-600 flex items-center justify-center hover:bg-gray-200 dark:hover:bg-gray-600 hover:border-gray-400 dark:hover:border-gray-500 transition shadow-sm opacity-0 group-hover:opacity-100 focus:opacity-100"
				title="Copy to clipboard"
			>
				{#if copiedMessageId === msg.id}
					<svg class="w-3.5 h-3.5 text-green-500" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
						<path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
					</svg>
				{:else}
					<svg class="w-3.5 h-3.5 text-gray-500 dark:text-gray-400" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24">
						<path stroke-linecap="round" stroke-linejoin="round" d="M15.666 3.888A2.25 2.25 0 0013.5 2.25h-3c-1.03 0-1.9.693-2.166 1.638m7.332 0c.055.194.084.4.084.612v0a.75.75 0 01-.75.75H9a.75.75 0 01-.75-.75v0c0-.212.03-.418.084-.612m7.332 0c.646.049 1.288.11 1.927.184 1.1.128 1.907 1.077 1.907 2.185V19.5a2.25 2.25 0 01-2.25 2.25H6.75A2.25 2.25 0 014.5 19.5V6.257c0-1.108.806-2.057 1.907-2.185a48.208 48.208 0 011.927-.184" />
					</svg>
				{/if}
			</button>
			<!-- Copied tooltip -->
			{#if copiedMessageId === msg.id}
				<div class="absolute -bottom-8 right-0 px-2 py-1 bg-gray-900 dark:bg-gray-600 text-white text-xs rounded shadow-lg whitespace-nowrap">
					Copied!
				</div>
			{/if}
		{/if}

		<!-- Copy button for user messages -->
		{#if msg.role === 'user'}
			<button
				on:click={() => copyMessageToClipboard(msg)}
				class="absolute -bottom-2 right-2 w-6 h-6 rounded-full bg-gray-100 dark:bg-gray-700 border border-gray-300 dark:border-gray-600 flex items-center justify-center hover:bg-gray-200 dark:hover:bg-gray-600 hover:border-gray-400 dark:hover:border-gray-500 transition shadow-sm opacity-0 group-hover:opacity-100 focus:opacity-100"
				title="Copy to clipboard"
			>
				{#if copiedMessageId === msg.id}
					<svg class="w-3.5 h-3.5 text-green-500" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
						<path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
					</svg>
				{:else}
					<svg class="w-3.5 h-3.5 text-gray-500 dark:text-gray-400" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24">
						<path stroke-linecap="round" stroke-linejoin="round" d="M15.666 3.888A2.25 2.25 0 0013.5 2.25h-3c-1.03 0-1.9.693-2.166 1.638m7.332 0c.055.194.084.4.084.612v0a.75.75 0 01-.75.75H9a.75.75 0 01-.75-.75v0c0-.212.03-.418.084-.612m7.332 0c.646.049 1.288.11 1.927.184 1.1.128 1.907 1.077 1.907 2.185V19.5a2.25 2.25 0 01-2.25 2.25H6.75A2.25 2.25 0 014.5 19.5V6.257c0-1.108.806-2.057 1.907-2.185a48.208 48.208 0 011.927-.184" />
					</svg>
				{/if}
			</button>
			<!-- Copied tooltip -->
			{#if copiedMessageId === msg.id}
				<div class="absolute -bottom-8 right-0 px-2 py-1 bg-gray-900 dark:bg-gray-600 text-white text-xs rounded shadow-lg whitespace-nowrap">
					Copied!
				</div>
			{/if}
		{/if}
			</div>
		</div>
	{/each}
	
	<!-- Loading spinners for pending bots (waiting for first token) -->
	{#each activeBots.filter(b => pendingBots.has(b.id)) as bot (bot.id)}
		<div class="flex justify-start">
			<div class="max-w-[80%] p-3 rounded-2xl bg-gray-100 dark:bg-gray-700 rounded-bl-md">
				<div class="flex items-center gap-2 text-xs text-gray-500 dark:text-gray-400 mb-2">
					<span class="font-medium">{bot.name || bot.model}</span>
					<span>•</span>
					<span>{formatProviderName(bot.provider)}</span>
					{#if bot.webSearchEnabled}
						<span title="Web search enabled">
							<svg class="w-3.5 h-3.5 text-brand" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24">
								<path stroke-linecap="round" stroke-linejoin="round" d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5a17.919 17.919 0 01-8.716-2.247m0 0A9.015 9.015 0 013 12c0-1.605.42-3.113 1.157-4.418" />
							</svg>
						</span>
					{/if}
				</div>
				<div class="flex items-center gap-2 text-gray-500 dark:text-gray-400">
					<!-- Animated loading dots -->
					<div class="flex items-center gap-1">
						<span class="w-2 h-2 bg-gray-400 dark:bg-gray-500 rounded-full animate-bounce" style="animation-delay: 0ms;"></span>
						<span class="w-2 h-2 bg-gray-400 dark:bg-gray-500 rounded-full animate-bounce" style="animation-delay: 150ms;"></span>
						<span class="w-2 h-2 bg-gray-400 dark:bg-gray-500 rounded-full animate-bounce" style="animation-delay: 300ms;"></span>
					</div>
					<span class="text-sm">{bot.webSearchEnabled ? 'Searching & thinking...' : 'Thinking...'}</span>
				</div>
			</div>
		</div>
	{/each}
</div>

<!-- Citations Popup -->
<CitationsPopup 
	citations={selectedCitations} 
	isOpen={showCitationsPopup} 
	on:close={closeCitations}
/>

<style>
	/* Ensure tooltip text breaks properly */
	:global(.prose) {
		overflow-wrap: break-word;
		word-break: break-word;
	}
	
	/* Code block wrapper styles - Light theme */
	:global(.code-block-wrapper) {
		position: relative;
		margin-bottom: 0.5rem;
		border-radius: 0.5rem;
		overflow: hidden;
		background: #f8f8f8;
		border: 1px solid #e5e7eb;
	}
	
	:global(.code-block-header) {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 0.5rem 0.75rem;
		background: #f0f0f0;
		border-bottom: 1px solid #e5e7eb;
	}
	
	:global(.code-lang) {
		font-size: 0.7rem;
		font-weight: 500;
		color: #6b7280;
		text-transform: lowercase;
		font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
	}
	
	:global(.copy-btn) {
		display: flex;
		align-items: center;
		gap: 0.35rem;
		padding: 0.25rem 0.5rem;
		font-size: 0.7rem;
		color: #6b7280;
		background: transparent;
		border: none;
		border-radius: 0.25rem;
		cursor: pointer;
		transition: all 0.15s;
	}
	
	:global(.copy-btn:hover) {
		color: #374151;
		background: #e5e7eb;
	}
	
	:global(.copy-btn .hidden) {
		display: none;
	}
	
	:global(.copy-text) {
		font-family: ui-sans-serif, system-ui, sans-serif;
	}
	
	:global(.code-block-wrapper pre) {
		margin: 0 !important;
		padding: 0.75rem !important;
		background: #f8f8f8 !important;
		overflow-x: auto;
	}
	
	:global(.code-block-wrapper code) {
		font-size: 0.8rem;
		line-height: 1.5;
		font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
	}
	
	/* VS Code Light+ inspired syntax highlighting theme */
	:global(.hljs) {
		color: #383a42;
		background: #f8f8f8;
	}
	
	:global(.hljs-keyword),
	:global(.hljs-selector-tag),
	:global(.hljs-literal),
	:global(.hljs-section),
	:global(.hljs-link) {
		color: #0000ff;
	}
	
	:global(.hljs-function) {
		color: #795e26;
	}
	
	:global(.hljs-string),
	:global(.hljs-title),
	:global(.hljs-name),
	:global(.hljs-type),
	:global(.hljs-attribute),
	:global(.hljs-symbol),
	:global(.hljs-bullet),
	:global(.hljs-addition),
	:global(.hljs-variable),
	:global(.hljs-template-tag),
	:global(.hljs-template-variable) {
		color: #a31515;
	}
	
	:global(.hljs-comment),
	:global(.hljs-quote),
	:global(.hljs-deletion),
	:global(.hljs-meta) {
		color: #008000;
	}
	
	:global(.hljs-keyword),
	:global(.hljs-selector-tag),
	:global(.hljs-literal),
	:global(.hljs-title),
	:global(.hljs-section),
	:global(.hljs-doctag),
	:global(.hljs-type),
	:global(.hljs-name),
	:global(.hljs-strong) {
		font-weight: normal;
	}
	
	:global(.hljs-number),
	:global(.hljs-class .hljs-title) {
		color: #098658;
	}
	
	:global(.hljs-built_in),
	:global(.hljs-class) {
		color: #267f99;
	}
	
	:global(.hljs-params) {
		color: #001080;
	}
	
	:global(.hljs-regexp) {
		color: #811f3f;
	}
	
	:global(.hljs-attr) {
		color: #001080;
	}
	
	:global(.hljs-punctuation) {
		color: #383a42;
	}
	
	/* Code block wrapper styles - Dark theme */
	:global(.dark .code-block-wrapper) {
		background: #1e1e1e;
		border: 1px solid #3d3d3d;
	}
	
	:global(.dark .code-block-header) {
		background: #2d2d2d;
		border-bottom: 1px solid #3d3d3d;
	}
	
	:global(.dark .code-lang) {
		color: #9ca3af;
	}
	
	:global(.dark .copy-btn) {
		color: #9ca3af;
	}
	
	:global(.dark .copy-btn:hover) {
		color: #e5e7eb;
		background: #3d3d3d;
	}
	
	:global(.dark .code-block-wrapper pre) {
		background: #1e1e1e !important;
	}
	
	/* VS Code Dark+ inspired syntax highlighting theme */
	:global(.dark .hljs) {
		color: #d4d4d4;
		background: #1e1e1e;
	}
	
	:global(.dark .hljs-keyword),
	:global(.dark .hljs-selector-tag),
	:global(.dark .hljs-literal),
	:global(.dark .hljs-section),
	:global(.dark .hljs-link) {
		color: #569cd6;
	}
	
	:global(.dark .hljs-function) {
		color: #dcdcaa;
	}
	
	:global(.dark .hljs-string),
	:global(.dark .hljs-title),
	:global(.dark .hljs-name),
	:global(.dark .hljs-type),
	:global(.dark .hljs-attribute),
	:global(.dark .hljs-symbol),
	:global(.dark .hljs-bullet),
	:global(.dark .hljs-addition),
	:global(.dark .hljs-variable),
	:global(.dark .hljs-template-tag),
	:global(.dark .hljs-template-variable) {
		color: #ce9178;
	}
	
	:global(.dark .hljs-comment),
	:global(.dark .hljs-quote),
	:global(.dark .hljs-deletion),
	:global(.dark .hljs-meta) {
		color: #6a9955;
	}
	
	:global(.dark .hljs-number),
	:global(.dark .hljs-class .hljs-title) {
		color: #b5cea8;
	}
	
	:global(.dark .hljs-built_in),
	:global(.dark .hljs-class) {
		color: #4ec9b0;
	}
	
	:global(.dark .hljs-params) {
		color: #9cdcfe;
	}
	
	:global(.dark .hljs-regexp) {
		color: #d16969;
	}
	
	:global(.dark .hljs-attr) {
		color: #9cdcfe;
	}
	
	:global(.dark .hljs-punctuation) {
		color: #d4d4d4;
	}
	
	:global(.hljs-property) {
		color: #9cdcfe;
	}
	
	:global(.hljs-operator) {
		color: #d4d4d4;
	}
	
	:global(.hljs-title.function_) {
		color: #dcdcaa;
	}
	
	:global(.hljs-title.class_) {
		color: #4ec9b0;
	}
</style>
