// Service worker restrito à pasta MarketMap. Não intercepta o CRM nem o Firebase.
self.addEventListener('install',event=>{self.skipWaiting();});
self.addEventListener('activate',event=>{event.waitUntil(self.clients.claim());});
// Funcionalidades Firebase/Google Maps exigem rede e autenticação. Sem cache de dados comerciais.
