"use strict";

// Makes Telltale installable so Android lists it in the share sheet. Nothing is cached:
// every request goes to the network, so a verdict can never come from a stale copy.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));
self.addEventListener("fetch", () => {});
