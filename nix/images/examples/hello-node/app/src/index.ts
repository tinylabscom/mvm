import { createServer, IncomingMessage, ServerResponse } from "http";

const PORT = parseInt(process.env["PORT"] ?? "3000", 10);

const server = createServer((_req: IncomingMessage, res: ServerResponse) => {
  const body = JSON.stringify({ message: "Hello from microVM!", port: PORT });
  res.writeHead(200, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(body),
  });
  res.end(body);
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`[hello-node] listening on :${PORT}`);
});
