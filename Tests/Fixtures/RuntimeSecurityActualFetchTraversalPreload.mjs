import dns from "node:dns";
import tls from "node:tls";

const originalTLSConnect = tls.connect;
globalThis.__localHarnessActualFetchTLSCalls = 0;
globalThis.__localHarnessActualFetchDNSCalls = 0;
globalThis.__localHarnessActualFetchLookupSeen = false;

dns.lookup = function actualFetchDNSFixture(hostname, options, callback) {
  globalThis.__localHarnessActualFetchDNSCalls += 1;
  const resolvedOptions = typeof options === "object" && options !== null ? options : {};
  const resolvedCallback = typeof options === "function" ? options : callback;
  const answer = { address: "93.184.216.34", family: 4 };
  queueMicrotask(() => resolvedOptions.all === true
    ? resolvedCallback(null, [answer])
    : resolvedCallback(null, answer.address, answer.family));
};

tls.connect = function actualFetchTLSFixture(...args) {
  globalThis.__localHarnessActualFetchTLSCalls += 1;
  const options = args.find((value) => value && typeof value === "object" && !Array.isArray(value));
  if (typeof options?.lookup === "function") globalThis.__localHarnessActualFetchLookupSeen = true;
  return originalTLSConnect.apply(this, args);
};
