// ==UserScript==
// @name         Discourse: Ignore Hidden Profile Button
// @namespace    https://ntc.party/
// @version      1.0
// @description  Добавляет кнопку "Игнорировать" на скрытом профиле Discourse. Копирует имя пользователя и открывает настройки игнорирования в новой вкладке.
// @match        https://ntc.party/u/*/profile-hidden
// @grant        GM_setClipboard
// ==/UserScript==

(function () {
    'use strict';

    // Получаем имя пользователя из URL
    const pathParts = location.pathname.split('/');
    const username = pathParts[2];
    if (!username) return;

    // Создаём кнопку
    const btn = document.createElement('button');
    btn.textContent = `🚫 Игнорировать пользователя @${username}`;
    btn.style = `
        margin: 20px auto;
        padding: 10px 16px;
        background: #d33;
        color: white;
        border: none;
        border-radius: 6px;
        font-size: 16px;
        cursor: pointer;
        display: block;
    `;

    // При клике — копируем ник и открываем настройки
    btn.onclick = () => {
        GM_setClipboard(username, 'text');
        alert(`Пользователь @${username} скопирован в буфер.\nОткроется страница для добавления в список игнорируемых.`);
        window.open('https://ntc.party/u/ТВОЙ_НИК/preferences/users', '_blank');
    };

    // Вставляем кнопку в DOM
    const container = document.querySelector('.user-main') || document.body;
    container.appendChild(btn);
})();
