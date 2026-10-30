# docsify-auth

A single-password authorization plugin for [Docsify](https://docsify.js.org). Locks your documentation behind a fullscreen login screen, withholds page content until the correct password is entered, and adds a **Log out** button to the sidebar. No backend, no accounts, no multi-user — one shared password for a private docs site on any static hosting.

## Features

- Fullscreen lock screen (dark gradient + white card) until the user is authenticated
- Markdown content is **never rendered into the DOM** before login (`beforeEach` hook)
- Password is stored only as a **SHA-256 hash** — no plaintext in your source
- WebCrypto hashing with a built-in pure-JS fallback (works even on `file://`)
- Session lives in `sessionStorage` — it dies when the tab is closed
- Logout button injected into the sidebar (optional)
- Single file (~20 KB), zero dependencies

## Installation

Script order matters: config first, then Docsify, then the plugin.

```html
<script>
  window.$docsify = {
    // ...your config...
    auth: {
      passwordHash: '<64 hex chars — SHA-256 of your password>',
      // optional overrides (defaults are Russian):
      title: 'Private docs',
      subtitle: 'Enter the password to continue',
      placeholder: 'Password',
      buttonText: 'Sign in',
      errorMessage: 'Wrong password. Try again.',
      logoutText: 'Log out'
    }
  };
</script>
<script src="https://cdn.jsdelivr.net/npm/docsify@4"></script>
<script src="docsify-auth.js"></script>
```

## Setting the password

The plugin compares `crypto.subtle.digest('SHA-256', input)` against `passwordHash`, so you only commit the hash, never the password.

**Option 1 — browser console.** Open your docs site (even the lock screen) and run:

```js
DocsifyAuth.sha256('my password').then(console.log)
```

**Option 2 — terminal:**

```bash
echo -n 'my password' | sha256sum
```

> **Important:** `echo -n` matters — without it a trailing newline is hashed and you get a different hash.

Paste the 64-character hex string into `auth.passwordHash`. Log out (or close the tab) after changing the hash — an already-open tab keeps its session.

## Options

| Option         | Type    | Default                                | Description                                      |
| -------------- | ------- | -------------------------------------- | ------------------------------------------------ |
| `passwordHash` | string  | `''`                                   | SHA-256 of the password, 64 hex chars. Required. |
| `storageKey`   | string  | `'docsify-auth-session'`               | `sessionStorage` key for the session flag.       |
| `title`        | string  | `'Закрытая документация'`              | Lock screen heading.                             |
| `subtitle`     | string  | `'Введите пароль, чтобы продолжить'`   | Lock screen subheading.                          |
| `placeholder`  | string  | `'Пароль'`                             | Password input placeholder.                      |
| `buttonText`   | string  | `'Войти'`                              | Submit button label.                             |
| `errorMessage` | string  | `'Неверный пароль...'`                 | Message on a wrong password.                     |
| `hashErrorText` | string | `'Ошибка конфигурации...'`             | Message shown when `passwordHash` is misconfigured. |
| `logout`       | boolean | `true`                                 | Show the logout button in the sidebar.           |
| `logoutText`   | string  | `'Выйти'`                              | Logout button label.                             |
| `accent`       | string  | `'#42b983'`                            | Accent color of the card, button and glow.       |

## How it works

- **Locked:** the plugin's `beforeEach` hook returns an empty string, so Docsify never renders your markdown, and an opaque fullscreen overlay covers the page.
- **Correct password:** the SHA-256 hex is compared against `passwordHash` (constant-time string compare); a session flag is written to `sessionStorage` and the page reloads authenticated.
- **Wrong password:** the card shakes, an error message appears, the input is cleared and refocused.
- **Until the tab closes:** reloading or navigating inside the site keeps the session; closing the tab ends it.
- **Logout:** the sidebar button (or `DocsifyAuth.logout()` in the console) clears the session and reloads to the lock screen.

## FAQ

**How do I change the password?**
Generate a new hash (see above), replace `passwordHash`, deploy. Open tabs stay logged in until closed or logged out.

**I forgot the password.**
Set a new hash and redeploy — that's it. There is no recovery because the plaintext is never stored anywhere.

**Can I have several users or usernames?**
No, by design. One shared password. If you need per-user access, you need server-side auth (reverse proxy, Basic Auth, OAuth) — not a static-site plugin.

**Is this real security?**
No. It's a client-side gate for static hosting: it keeps random visitors out of the UI, but your `.md` files remain downloadable by direct URL, and all checks run in the visitor's browser. For genuinely private docs, put server-side auth in front of the hosting (e.g. Basic Auth on nginx, Cloudflare Access, or a gated bucket).

**The default texts are in Russian. Can I localize the screen?**
Yes — every visible string is configurable (see the options table and the installation example).

**Which versions are supported?**
Docsify v4.x in modern browsers. WebCrypto is used when available; otherwise a built-in JS SHA-256 implementation takes over, so `file://` and older environments work too.

## Security notes

- Only the SHA-256 hash ships with the site; the plaintext never leaves the user's browser.
- The comparison uses a constant-time algorithm to avoid trivial timing leaks.
- Remember: this is convenience-level protection, not access control. Anyone with the direct file URL can still fetch raw markdown — see the FAQ.

## License

MIT
