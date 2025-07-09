// ==UserScript==
// @name         Discourse: Mark Hidden Profiles (All Pages)
// @namespace    https://ntc.party/
// @version      1.2
// @description  Помечает пользователей с закрытым профилем на всех страницах Discourse (темы, список пользователей, топики). Кеширует результат на 7 дней.
// @author       GPT
// @match        https://ntc.party/t/*
// @match        https://ntc.party/latest
// @match        https://ntc.party/top*
// @match        https://ntc.party/users*
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

    function markElement(el, username) {
        el.style.backgroundColor = '#eee';
        if (!el.innerText.includes('[Профиль скрыт]')) {
            el.innerText += ' [Профиль скрыт]';
        }
    }

    function markAllElements(username) {
        document.querySelectorAll(`a[href^="/u/${username}"]`).forEach(el => {
            markElement(el, username);
        });
    }

    function checkUser(username) {
        const now = Date.now();
        if (cache[username]) {
            if (now - cache[username].ts < CACHE_TTL) {
                if (cache[username].hidden) markAllElements(username);
                return;
            }
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
                    saveCache();
                    markAllElements(username);
                }
            }
        });
    }

    function extractUsernames() {
        const found = new Set();
        document.querySelectorAll('a[href^="/u/"]').forEach(link => {
            const match = link.getAttribute('href').match(/^\/u\/([^\/\?#]+)/);
            if (match) found.add(match[1]);
        });
        return [...found];
    }

    function scanPage() {
        extractUsernames().forEach(username => {
            checkUser(username);
        });
    }

    scanPage();
    setInterval(scanPage, 5000);
})();
