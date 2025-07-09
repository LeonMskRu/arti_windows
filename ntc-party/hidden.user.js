// ==UserScript==
// @name         Discourse: Hide Users with Hidden Profile
// @namespace    https://ntc.party/
// @version      1.0
// @description  Скрывает посты пользователей с закрытым профилем на форумах Discourse
// @author       GPT
// @match        https://ntc.party/t/*
// @grant        GM_xmlhttpRequest
// @connect      ntc.party
// ==/UserScript==

(function () {
    'use strict';

    const HIDDEN_MSG = 'Публичный профиль пользователя скрыт';
    const checkedUsers = {};

    function hidePost(el) {
        el.style.display = 'none';
    }

    function processPost(post) {
        const userLink = post.querySelector('a.trigger-user-card');
        if (!userLink) return;

        const username = userLink.getAttribute('href')?.split('/u/')[1]?.replace(/\/.*/, '');
        if (!username || checkedUsers[username]) return;

        checkedUsers[username] = 'checking';

        GM_xmlhttpRequest({
            method: 'GET',
            url: `https://ntc.party/u/${username}`,
            onload: function (res) {
                if (res.responseText.includes(HIDDEN_MSG)) {
                    console.log(`🛑 Hidden profile detected: ${username}`);
                    const allPosts = document.querySelectorAll(`article[data-user-card="${username}"]`);
                    allPosts.forEach(hidePost);
                    checkedUsers[username] = 'hidden';
                } else {
                    checkedUsers[username] = 'visible';
                }
            },
        });
    }

    function scanAllPosts() {
        document.querySelectorAll('article[data-user-card]').forEach(processPost);
    }

    // Initial scan
    scanAllPosts();

    // Re-scan every 5 seconds for lazy-loaded posts
    setInterval(scanAllPosts, 5000);
})();
