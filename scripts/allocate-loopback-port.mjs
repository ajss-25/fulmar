import net from "node:net";

const excluded = new Set();
for (let index = 2; index < process.argv.length; index += 1) {
  if (process.argv[index] !== "--exclude" || index + 1 >= process.argv.length) process.exit(64);
  const port = Number(process.argv[index + 1]);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) process.exit(64);
  excluded.add(port);
  index += 1;
}

async function allocate() {
  for (let attempt = 0; attempt < 16; attempt += 1) {
    const server = net.createServer();
    server.unref();
    const port = await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen({ host: "127.0.0.1", port: 0, exclusive: true }, () => {
        const address = server.address();
        resolve(typeof address === "object" && address ? address.port : 0);
      });
    });
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    if (Number.isSafeInteger(port) && port >= 1024 && port <= 65535 && !excluded.has(port)) {
      process.stdout.write(`${port}\n`);
      return;
    }
  }
  throw new Error("could not allocate an excluded-port-safe loopback fixture port");
}

await allocate();
