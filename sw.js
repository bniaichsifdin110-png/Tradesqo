self.addEventListener("install",()=>self.skipWaiting());
self.addEventListener("activate",e=>e.waitUntil(clients.claim()));
self.addEventListener("fetch",e=>{
  if(e.request.method!=="GET"||e.request.url.includes("/api/"))return;
  e.respondWith(fetch(e.request).then(r=>{const c=r.clone();caches.open("v1").then(x=>x.put(e.request,c));return r}).catch(()=>caches.match(e.request)));
});
