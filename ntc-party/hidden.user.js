// ==UserScript==
// @name         Discourse: Mark Users with Hidden Profile
// @namespace    https://ntc.party/
// @version      1.1
// @description  Помечает посты пользователей с закрытым профилем (Discourse). Кеширует результат на 7 дней.
// @author       GPT
// @match        https://ntc.party/t/*
// @grant        GM_xmlhttpRequest
// @connect      ntc.party
// ==/UserScript==

(function () {
    'use strict';

    const HIDDEN_MSG = 'Публичный профиль пользователя скрыт';
    const CACHE_KEY = 'hidden_profile_cache';
    const CACHE_TTL = 7 * 24 * 60 * 60 * 1000; // 7 дней

    let cache = {};
    try {
        cache = JSON.parse(localStorage.getItem(CACHE_KEY)) || {};
    } catch (e) {
        cache = {};
    }

    function saveCache() {
        localStorage.setItem(CACHE_KEY, JSON.stringify(cache));
    }

    function markAsHidden(post, username) {
        post.style.backgroundColor = '#eee';
        const nameEl = post.querySelector('a.trigger-user-card');
        if (nameEl && !nameEl.innerText.includes('[Профиль скрыт]')) {
            nameEl.innerText += ' [Профиль скрыт]';
        }
    }

    function processPost(post) {
        const userLink = post.querySelector('a.trigger-user-card');
        if (!userLink) return;

        const username = userLink.getAttribute('href')?.split('/u/')[1]?.replace(/\/.*/, '');
        if (!username) return;
        const now = Date.now();

        if (cache[username]) {
            if (now - cache[username].ts < CACHE_TTL && cache[username].hidden) {
                markAsHidden(post, username);
            }
            return;
        }

        cache[username] = { ts: now, hidden: false };
        saveCache();

        GM_xmlhttpRequest({
            method: 'GET',
            url: `https://ntc.party/u/${username}`,
            onload: function (res) {
                if (res.responseText.includes(HIDDEN_MSG)) {
                    console.log(`🛑 Скрытый профиль: ${username}`);
                    cache[username].hidden = true;
                    cache[username].ts = Date.now();
                    markAsHidden(post, username);
                    saveCache();
                }
            },
        });
    }

    function scanAllPosts() {
        document.querySelectorAll('article[data-user-card]').forEach(processPost);
    }

    scanAllPosts();
    setInterval(scanAllPosts, 5000);
})();
