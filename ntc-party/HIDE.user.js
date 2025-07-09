// ==UserScript==
// @name         Discourse: Ignore & Mark Hidden Profiles (All-in-1)
// @namespace    https://ntc.party/
// @version      3.2
// @description  Кнопка игнора на /profile-hidden, массовая проверка на /latest/top/c/t. Работает в Firefox + Tampermonkey. Автокеш, GM_openInTab.
// @match        https://ntc.party/u/*/profile-hidden
// @match        https://ntc.party/latest*
// @match        https://ntc.party/top*
// @match        https://ntc.party/c/*
// @match        https://ntc.party/t/*
// @grant        GM_setClipboard
// @grant        GM_openInTab
// @grant        GM_xmlhttpRequest
// @connect      ntc.party
// ==/UserScript==

(function(){
  'use strict';

  const HIDDEN_MSG = 'Публичный профиль пользователя скрыт';
  const CACHE_KEY = 'hidden_profile_cache';
  const TTL = 7*24*60*60*1000; // 7 дней

  let cache = {};
  try{ cache = JSON.parse(localStorage.getItem(CACHE_KEY))||{} }catch(e){ cache={} }
  function saveCache(){ localStorage.setItem(CACHE_KEY, JSON.stringify(cache)) }

  function getMyName(){
    const el = document.querySelector('a.header-dropdown-toggle[href^="/u/"]');
    return el?.href.split('/u/')[1].replace(/\/.*/,'') || '';
  }
  const myName = getMyName();

  function markPost(el){
    if(el.dataset.hiddenMarked)return;
    el.dataset.hiddenMarked = '1';
    el.style.backgroundColor = '#eee';
    const userLink = el.querySelector('a.trigger-user-card');
    if(userLink && !userLink.innerText.includes('[скрыт]')){
      userLink.innerHTML = userLink.innerHTML.replace(/(<\/?[^>]+>)/g, '\x01').replace(/[^\x01]+/g, m => 
        m + (m.trim() ? ' [скрыт]' : '')
        .replace(/\x01/g, '<>').split('<>').join('$1');
    }
  }

  function markAll(username){
    document.querySelectorAll(`article[data-user-card="${username}"]`).forEach(markPost);
  }

  function checkUser(username){
    const now = Date.now();
    if(cache[username] && now - cache[username].ts < TTL){
      if(cache[username].hidden) markAll(username);
      return Promise.resolve(cache[username].hidden);
    }
    cache[username] = { ts: now, hidden: false };
    saveCache();
    return new Promise(resolve=>{
      GM_xmlhttpRequest({
        method:'GET', url:`https://ntc.party/u/${username}`,
        onload(res){
          if(res.responseText.includes(HIDDEN_MSG)){
            cache[username].hidden = true;
            markAll(username);
          }
          cache[username].ts = Date.now();
          saveCache();
          resolve(cache[username].hidden);
        },
        onerror(){ resolve(false) },
        ontimeout(){ resolve(false) }
      });
    });
  }

  // --- 1. Страница скрытого профиля ---
  if(location.pathname.match(/^\/u\/[^\/]+\/profile-hidden$/)){
    const username = location.pathname.split('/')[2];
    const btn = document.createElement('button');
    btn.textContent = `🚫 Игнорировать @${username}`;
    btn.style = `
      margin:20px auto; padding:10px 16px;
      background:#d33; color:#fff; border:none; border-radius:6px;
      font-size:16px; cursor:pointer; display:block;
    `;
    btn.onclick = () => {
      GM_setClipboard(username, 'text');
      alert(`@${username} скопирован. Откроется страница игнорирования в фоне.`);
      if (myName) GM_openInTab(`https://ntc.party/u/${myName}/preferences/users`, { active: false });
    };
    (document.querySelector('.user-main') || document.body).appendChild(btn);
    return;
  }

  // --- 2. Массовая кнопка на страницах с постами ---
  const btn = document.createElement('button');
  btn.textContent = '🚫 Пометить & собрать скрытые профили';
  btn.style = `
    position: sticky; top:0; z-index:999;
    width:100%; padding:8px 0;
    background:#cc0000; color:#fff; border:none;
    font-size:16px; cursor:pointer;
  `;
  document.body.insertBefore(btn, document.body.firstChild);

  btn.addEventListener('click', async () => {
    btn.disabled = true;
    const links = Array.from(document.querySelectorAll('a.trigger-user-card'));
    const users = [...new Set(links.map(a => a.href.split('/u/')[1].replace(/\/.*/, '')))];
    const hidden = [];
    for (let i = 0; i < users.length; i++) {
      btn.textContent = `Проверено ${i + 1}/${users.length}… Найдено скрытых: ${hidden.length}`;
      // eslint-disable-next-line no-await-in-loop
      const isHidden = await checkUser(users[i]);
      if (isHidden) hidden.push(users[i]);
    }
    if (hidden.length) {
      GM_setClipboard(hidden.join('; '), 'text');
      alert(`Скрытых: ${hidden.length}\nСкопировано в буфер:\n${hidden.join('; ')}\nОткроется страница игнорирования в фоне.`);
      if (myName) GM_openInTab(`https://ntc.party/u/${myName}/preferences/users`, { active: false });
    } else {
      alert('Скрытых профилей не найдено.');
    }
    btn.textContent = '🚫 Пометить & собрать скрытые профили';
    btn.disabled = false;
  });

  // Автопометка из кеша
  document.querySelectorAll('a.trigger-user-card').forEach(a => {
    const user = a.href.split('/u/')[1].replace(/\/.*/, '');
    if (cache[user]?.hidden) markAll(user);
  });

  // Открытие профилей в новой вкладке
  document.addEventListener('click', function(e) {
    const userCard = e.target.closest('a.trigger-user-card');
    if (userCard) {
      e.preventDefault();
      const username = userCard.href.split('/u/')[1].replace(/\/.*/, '');
      GM_openInTab(`https://ntc.party/u/${username}/summary`, { active: true });
    }
  });

})();