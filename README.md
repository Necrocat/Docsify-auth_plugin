# Docsify-auth_plugin
docsify плагин для авторизации для версии 5

Правила подключения в index.html:

<script>
  window.$docsify = {
    // ...ваша конфигурация...
    auth: {
      passwordHash: 'ecd71870d1963316a97e3ac3408c9835ad8cf0f3c1bc703527c30265534f75ae'
    }
  };
</script>
<script src="https://cdn.jsdelivr.net/npm/docsify@4"></script>
<script src="docsify-auth.js"></script>
