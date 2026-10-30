/*!
 * docsify-auth.js v1.0.0 — плагин авторизации для Docsify (один пользователь)
 * Лицензия: MIT
 *
 * ПОДКЛЮЧЕНИЕ (порядок важен: сначала конфиг, потом docsify, потом плагин):
 *
 *   <script>
 *     window.$docsify = {
 *       // ...ваша конфигурация...
 *       auth: {
 *         passwordHash: 'ecd71870d1963316a97e3ac3408c9835ad8cf0f3c1bc703527c30265534f75ae'
 *         // ↑ SHA-256 вашего пароля в hex (64 символа)
 *       }
 *     };
 *   </script>
 *   <script src="https://cdn.jsdelivr.net/npm/docsify@4"></script>
 *   <script src="docsify-auth.js"></script>
 *
 * КАК ПОЛУЧИТЬ ХЕШ ПАРОЛЯ (не храните пароль открытым текстом):
 *   1) Откройте сайт документации и выполните в консоли браузера:
 *        DocsifyAuth.sha256('мой пароль').then(console.log)
 *   2) Или в терминале:
 *        echo -n 'мой пароль' | sha256sum
 *   (echo без -n добавит перевод строки и хеш будет другим!)
 *
 * ОПЦИИ (window.$docsify.auth):
 *   passwordHash  — SHA-256 пароля в hex, обязательно
 *   storageKey    — ключ sessionStorage ('docsify-auth-session')
 *   title         — заголовок экрана входа ('Закрытая документация')
 *   subtitle      — подзаголовок ('Введите пароль, чтобы продолжить')
 *   placeholder   — placeholder поля пароля ('Пароль')
 *   buttonText    — текст кнопки входа ('Войти')
 *   errorMessage  — текст при неверном пароле
 *   logout        — показывать кнопку «Выйти» в сайдбаре (true)
 *   logoutText    — текст кнопки выхода ('Выйти')
 *   accent        — акцентный цвет карточки и кнопки ('#42b983')
 *
 * ПОВЕДЕНИЕ:
 *   • Пока нет входа — контент не отдаётся (hook.beforeEach отдаёт пустую
 *     строку), поверх страницы непрозрачный экран входа.
 *   • Сессия живёт в sessionStorage — до закрытия вкладки.
 *   • После успешного входа страница перезагружается и отдаёт контент.
 *   • Кнопка «Выйти» в сайдбаре сбрасывает сессию.
 *   • Пароль хранится только как SHA-256 хеш; проверка через WebCrypto,
 *     с чистым JS-фолбэком для file:// и старых браузеров.
 *
 * ОГРАНИЧЕНИЯ: это клиентская защита «от лишних глаз» для статического
 * хостинга. Сами .md-файлы остаются доступны по прямым URL — для настоящей
 * приватности нужен сервер (Basic Auth, reverse proxy) или шифрование
 * контента на сборке.
 */
(function (global) {
  'use strict';

  var VERSION = '1.0.0';
  var LOCK_ID = 'docsify-auth-lock';
  var LOGOUT_ID = 'docsify-auth-logout';
  var STYLE_ID = 'docsify-auth-style';

  var DEFAULTS = {
    passwordHash: '',
    storageKey: 'docsify-auth-session',
    title: 'Закрытая документация',
    subtitle: 'Введите пароль, чтобы продолжить',
    placeholder: 'Пароль',
    buttonText: 'Войти',
    errorMessage: 'Неверный пароль. Попробуйте ещё раз.',
    hashErrorText: 'Ошибка конфигурации: auth.passwordHash не задан или не является 64 hex-символами (SHA-256).',
    logout: true,
    logoutText: 'Выйти',
    accent: '#42b983'
  };

  var HASH_RE = /^[0-9a-f]{64}$/;

  var ICON_SVG =
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" ' +
    'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<rect x="4" y="10.5" width="16" height="9.5" rx="2.2"></rect>' +
    '<path d="M8 10.5V7.2A4 4 0 0 1 12 3.2a4 4 0 0 1 4 4v3.3"></path>' +
    '<circle cx="12" cy="15.2" r="1.4" fill="currentColor" stroke="none"></circle>' +
    '</svg>';

  /* ======================= Настройки ======================= */

  function getOptions() {
    var user = (global.$docsify && global.$docsify.auth) || {};
    var o = {};
    var k;
    for (k in DEFAULTS) {
      if (Object.prototype.hasOwnProperty.call(DEFAULTS, k)) o[k] = DEFAULTS[k];
    }
    for (k in user) {
      if (Object.prototype.hasOwnProperty.call(user, k)) o[k] = user[k];
    }
    if (typeof o.passwordHash === 'string') o.passwordHash = o.passwordHash.toLowerCase().trim();
    return o;
  }

  /* ======================= SHA-256 ======================= */

  function bytesToHex(bytes) {
    var hex = '';
    var i;
    for (i = 0; i < bytes.length; i++) {
      hex += (bytes[i] >>> 4).toString(16) + (bytes[i] & 15).toString(16);
    }
    return hex;
  }

  // Строка -> «бинарная строка» UTF-8 (каждый символ 0..255)
  function utf8(str) {
    try {
      return unescape(encodeURIComponent(str));
    } catch (e) {
      return String(str);
    }
  }

  /**
   * SHA-256 строки -> Promise<hex>. Использует WebCrypto, где доступно,
   * иначе — чистую JS-реализацию ниже (file://, старые браузеры, тесты).
   */
  function sha256(str) {
    try {
      if (global.crypto && global.crypto.subtle && typeof global.TextEncoder === 'function') {
        var bytes = new global.TextEncoder().encode(String(str));
        return global.crypto.subtle
          .digest('SHA-256', bytes)
          .then(
            function (buf) { return bytesToHex(new Uint8Array(buf)); },
            function () { return jsSha256(str); }
          );
      }
    } catch (e) { /* фолбэк ниже */ }
    return Promise.resolve(jsSha256(str));
  }

  // Чистая JS-реализация SHA-256 (FIPS 180-4), без внешних зависимостей.
  function jsSha256(str) {
    var msg = utf8(String(str));

    var K = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    var H = [
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ];

    function rotr(x, n) {
      return (x >>> n) | (x << (32 - n));
    }

    var bitLen = msg.length * 8;
    msg += String.fromCharCode(0x80);
    while (msg.length % 64 !== 56) msg += String.fromCharCode(0);

    var hi = Math.floor(bitLen / 4294967296);
    var lo = bitLen - hi * 4294967296;
    msg += String.fromCharCode((hi >>> 24) & 255, (hi >>> 16) & 255, (hi >>> 8) & 255, hi & 255);
    msg += String.fromCharCode((lo >>> 24) & 255, (lo >>> 16) & 255, (lo >>> 8) & 255, lo & 255);

    var w = new Array(64);
    var i, j;

    for (i = 0; i < msg.length; i += 64) {
      for (j = 0; j < 16; j++) {
        var q = i + j * 4;
        w[j] = ((msg.charCodeAt(q) << 24) | (msg.charCodeAt(q + 1) << 16) |
                (msg.charCodeAt(q + 2) << 8) | msg.charCodeAt(q + 3)) | 0;
      }
      for (j = 16; j < 64; j++) {
        var a15 = w[j - 15];
        var a2 = w[j - 2];
        var s0 = rotr(a15, 7) ^ rotr(a15, 18) ^ (a15 >>> 3);
        var s1 = rotr(a2, 17) ^ rotr(a2, 19) ^ (a2 >>> 10);
        w[j] = (w[j - 16] + s0 + w[j - 7] + s1) | 0;
      }

      var a = H[0], b = H[1], c = H[2], d = H[3];
      var e = H[4], f = H[5], g = H[6], h = H[7];

      for (j = 0; j < 64; j++) {
        var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        var ch = (e & f) ^ (~e & g);
        var t1 = (h + S1 + ch + K[j] + w[j]) | 0;
        var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + maj) | 0;

        h = g; g = f; f = e; e = (d + t1) | 0;
        d = c; c = b; b = a; a = (t1 + t2) | 0;
      }

      H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
      H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
    }

    var out = '';
    for (i = 0; i < 8; i++) out += ('00000000' + (H[i] >>> 0).toString(16)).slice(-8);
    return out;
  }

  function timingSafeEqual(a, b) {
    a = String(a);
    b = String(b);
    if (a.length !== b.length) return false;
    var diff = 0;
    var i;
    for (i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
  }

  /* ==================== Хранилище сессии ==================== */
  /* Основной вариант — sessionStorage («до закрытия вкладки»).
     Если он недоступен (жёсткие privacy-настройки), пробуем localStorage,
     затем память (сессия только до перезагрузки страницы). */

  var storageBackend = null;

  var memoryStorage = {
    _d: {},
    getItem: function (k) {
      return Object.prototype.hasOwnProperty.call(this._d, k) ? this._d[k] : null;
    },
    setItem: function (k, v) { this._d[k] = String(v); },
    removeItem: function (k) { delete this._d[k]; }
  };

  function getStorage() {
    if (storageBackend) return storageBackend;
    var candidates = [
      function () { return global.sessionStorage; },
      function () { return global.localStorage; }
    ];
    var i, api;
    for (i = 0; i < candidates.length; i++) {
      try {
        api = candidates[i]();
        api.setItem('__docsify_auth_probe__', '1');
        api.removeItem('__docsify_auth_probe__');
        storageBackend = api;
        return storageBackend;
      } catch (e) { /* пробуем следующий */ }
    }
    storageBackend = memoryStorage;
    return storageBackend;
  }

  function randomHex(nBytes) {
    try {
      if (global.crypto && typeof global.crypto.getRandomValues === 'function') {
        var arr = new Uint8Array(nBytes);
        global.crypto.getRandomValues(arr);
        return bytesToHex(arr);
      }
    } catch (e) { /* фолбэк ниже */ }
    var out = '';
    var i;
    for (i = 0; i < nBytes * 2; i++) out += '0123456789abcdef'[(Math.random() * 16) | 0];
    return out;
  }

  function saveSession(o) {
    try {
      getStorage().setItem(
        o.storageKey,
        JSON.stringify({ ok: true, t: Date.now(), r: randomHex(16) })
      );
    } catch (e) { /* без сессии — просто перезагрузка */ }
  }

  function clearSession(o) {
    try { getStorage().removeItem(o.storageKey); } catch (e) { /* ignore */ }
  }

  function isUnlocked(o) {
    try {
      var raw = getStorage().getItem(o.storageKey);
      if (!raw) return false;
      var s = JSON.parse(raw);
      return !!(s && s.ok === true && typeof s.t === 'number');
    } catch (e) {
      return false;
    }
  }

  /* ==================== Экран входа ==================== */

  function hexToRgba(hex, alpha) {
    var m = /^#?([0-9a-f]{6})$/i.exec(hex || '');
    if (!m) return 'rgba(66,185,131,' + alpha + ')';
    var n = parseInt(m[1], 16);
    return 'rgba(' + ((n >> 16) & 255) + ',' + ((n >> 8) & 255) + ',' + (n & 255) + ',' + alpha + ')';
  }

  function ensureStyles(o) {
    if (document.getElementById(STYLE_ID)) return;
    var accent = typeof o.accent === 'string' && o.accent ? o.accent : DEFAULTS.accent;

    var css = [
      '#' + LOCK_ID + '{--da-accent:' + accent + ';position:fixed;top:0;right:0;bottom:0;left:0;z-index:2147483000;display:flex;align-items:center;justify-content:center;padding:24px;background:radial-gradient(900px 520px at 12% 8%,' + hexToRgba(accent, 0.14) + ',transparent 55%),linear-gradient(135deg,#141b2b 0%,#1e1832 52%,#0c1120 100%);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;-webkit-font-smoothing:antialiased;}',
      '#' + LOCK_ID + ' *{box-sizing:border-box;}',
      '.da-card{width:100%;max-width:372px;background:#fff;color:#1d2536;border-radius:16px;padding:36px 32px 30px;text-align:center;box-shadow:0 30px 80px rgba(2,7,20,.55),0 6px 18px rgba(2,7,20,.35);}',
      '.da-icon{width:44px;height:44px;margin:0 auto 4px;color:var(--da-accent);}',
      '.da-icon svg{width:100%;height:100%;display:block;}',
      '.da-title{margin:10px 0 6px;font-size:20px;line-height:1.3;font-weight:700;letter-spacing:-.01em;}',
      '.da-subtitle{margin:0 0 22px;font-size:14px;line-height:1.5;color:#66707f;}',
      '.da-form{display:flex;flex-direction:column;gap:10px;}',
      '.da-input{width:100%;padding:12px 14px;font-size:15px;color:#1d2536;background:#f6f8fb;border:1.5px solid #dfe4ec;border-radius:10px;outline:none;transition:border-color .15s ease,box-shadow .15s ease;}',
      '.da-input:focus{border-color:var(--da-accent);background:#fff;box-shadow:0 0 0 3px ' + hexToRgba(accent, 0.18) + ';}',
      '.da-btn{padding:12px 14px;font-size:15px;font-weight:600;color:#fff;background:var(--da-accent);border:0;border-radius:10px;cursor:pointer;transition:filter .15s ease,transform .06s ease,opacity .15s ease;}',
      '.da-btn:hover{filter:brightness(1.05);}',
      '.da-btn:active{transform:translateY(1px);}',
      '.da-btn[disabled]{opacity:.6;cursor:default;transform:none;}',
      '.da-error{margin:14px 0 0;font-size:13px;line-height:1.45;color:#d64545;}',
      '.da-shake{animation:daShake .4s ease;}',
      '@keyframes daShake{20%{transform:translateX(-8px)}40%{transform:translateX(7px)}60%{transform:translateX(-5px)}80%{transform:translateX(3px)}}',
      '@media (prefers-reduced-motion:reduce){.da-shake{animation:none;}}',
      '#' + LOGOUT_ID + '{position:sticky;bottom:0;z-index:5;display:block;width:100%;margin-top:18px;padding:10px 0 0;font-size:13px;text-align:left;color:#9aa3b0;background:transparent;border:0;border-top:1px solid rgba(0,0,0,.07);cursor:pointer;transition:color .15s ease;}',
      '#' + LOGOUT_ID + ':hover{color:#d64545;}'
    ].join('\n');

    var style = document.createElement('style');
    style.id = STYLE_ID;
    style.textContent = css;
    document.head.appendChild(style);
  }

  function removeLock() {
    var el = document.getElementById(LOCK_ID);
    if (el && el.parentNode) el.parentNode.removeChild(el);
    document.documentElement.style.overflow = '';
  }

  function showLock(o) {
    if (document.getElementById(LOCK_ID)) return;
    ensureStyles(o);

    if (!HASH_RE.test(o.passwordHash)) {
      // Явная диагностика вместо «молчаливой» блокировки навсегда
      console.error('[docsify-auth] auth.passwordHash не задан или имеет неверный формат ' +
        '(ожидаются 64 hex-символа — SHA-256 пароля). Экран входа останется заблокированным.');
    }

    var root = document.createElement('div');
    root.id = LOCK_ID;
    root.setAttribute('role', 'dialog');
    root.setAttribute('aria-modal', 'true');
    root.setAttribute('aria-label', o.title);

    var card = document.createElement('div');
    card.className = 'da-card';

    card.innerHTML =
      '<div class="da-icon" aria-hidden="true">' + ICON_SVG + '</div>' +
      '<h1 class="da-title"></h1>' +
      '<p class="da-subtitle"></p>' +
      '<form class="da-form" novalidate>' +
      '<input class="da-input" type="password" autocomplete="current-password">' +
      '<button class="da-btn" type="submit"></button>' +
      '</form>' +
      '<p class="da-error" role="alert" hidden></p>';

    card.querySelector('.da-title').textContent = o.title;
    card.querySelector('.da-subtitle').textContent = o.subtitle;

    var input = card.querySelector('.da-input');
    input.placeholder = o.placeholder;
    input.setAttribute('aria-label', o.placeholder);

    var btn = card.querySelector('.da-btn');
    btn.textContent = o.buttonText;

    var err = card.querySelector('.da-error');
    var busy = false;

    card.querySelector('.da-form').addEventListener('submit', function (ev) {
      ev.preventDefault();
      if (busy) return;

      var pwd = input.value;
      if (!pwd) {
        input.focus();
        return;
      }

      busy = true;
      btn.disabled = true;

      sha256(pwd).then(function (hex) {
        var okHash = HASH_RE.test(o.passwordHash);

        if (okHash && timingSafeEqual(hex, o.passwordHash)) {
          saveSession(o);
          removeLock();
          global.location.reload(); // чистая инициализация уже авторизованной страницы
          return;
        }

        busy = false;
        btn.disabled = false;
        err.textContent = okHash ? o.errorMessage : o.hashErrorText;
        err.hidden = false;
        input.value = '';
        input.focus();
        card.classList.remove('da-shake');
        void card.offsetWidth; // перезапуск анимации
        card.classList.add('da-shake');
      })['catch'](function () {
        busy = false;
        btn.disabled = false;
        err.textContent = 'Не удалось выполнить проверку пароля.';
        err.hidden = false;
      });
    });

    root.appendChild(card);
    (document.body || document.documentElement).appendChild(root);
    document.documentElement.style.overflow = 'hidden'; // фон не скроллится

    setTimeout(function () { input.focus(); }, 0);
  }

  /* ==================== Кнопка «Выйти» ==================== */

  function injectLogout(o) {
    if (!o.logout || !isUnlocked(o)) return;

    var sidebar = document.querySelector('.sidebar');
    if (!sidebar || document.getElementById(LOGOUT_ID)) return;

    ensureStyles(o);

    var btn = document.createElement('button');
    btn.id = LOGOUT_ID;
    btn.type = 'button';
    btn.textContent = o.logoutText;
    btn.title = 'Завершить сессию docsify-auth';
    btn.addEventListener('click', function () {
      clearSession(o);
      global.location.reload();
    });

    sidebar.appendChild(btn);
  }

  /* ==================== Плагин docsify ==================== */

  function plugin(hook) {
    // Пока пользователь не вошёл, контент не отдаётся в DOM вовсе
    hook.beforeEach(function (content, next) {
      var o = getOptions();
      if (isUnlocked(o)) {
        next(content);
      } else {
        next('');
      }
    });

    hook.mounted(function () {
      injectLogout(getOptions());
    });

    hook.doneEach(function () {
      injectLogout(getOptions());
    });
  }

  /* ==================== Установка ==================== */

  global.$docsify = global.$docsify || {};
  global.$docsify.plugins = (global.$docsify.plugins || []).concat(plugin);

  // Небольшой публичный API: генерация хеша и программный выход
  global.DocsifyAuth = {
    version: VERSION,
    sha256: sha256,
    logout: function () {
      var o = getOptions();
      clearSession(o);
      global.location.reload();
    },
    _jsSha256: jsSha256 // внутреннее — для тестов
  };

  function boot() {
    if (typeof document === 'undefined') return; // не браузер (node-тесты)
    var o = getOptions();
    if (!isUnlocked(o)) showLock(o);
  }

  if (typeof document === 'undefined') {
    /* node: экран не нужен */
  } else if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})(typeof window !== 'undefined' ? window : typeof globalThis !== 'undefined' ? globalThis : this);
