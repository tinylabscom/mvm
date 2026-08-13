import init, {
  decide_egress,
  validate_network_policy,
  seal,
  hash_line,
  demo_capability_notice,
  demo_signing_key_hex,
  demo_verifying_key_hex,
} from "./pkg/mvm_demo_web.js";

// Single browser-tier microVM state. The demo only runs one VM at a time.
let vm = null;

const GENESIS_HASH_HEX = "0".repeat(64);

await init();
self.postMessage({
  type: "ready",
  capabilityNotice: demo_capability_notice(),
  verifyingKeyHex: demo_verifying_key_hex(),
});

self.onmessage = async (event) => {
  const { id, type } = event.data;
  try {
    let payload;
    switch (type) {
      case "launch":
        payload = await launchVm(event.data.configJson);
        break;
      case "stdin":
        payload = await sendStdin(event.data.line);
        break;
      case "stop":
        payload = stopVm();
        break;
      case "logs":
        payload = getLogs(event.data.lines);
        break;
      case "status":
        payload = getStatus();
        break;
      default:
        throw new Error(`unknown worker message type: ${type}`);
    }
    self.postMessage({ id, ok: true, payload });
  } catch (err) {
    self.postMessage({ id, ok: false, error: err.message });
  }
};

function base64UrlNoPad(bytes) {
  const base64 = btoa(String.fromCharCode(...bytes));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function nowTimestamp() {
  return new Date().toISOString();
}

function signAuditEntry(event, imageName, labels = {}) {
  const entry = {
    timestamp: nowTimestamp(),
    tenant: "browser-demo",
    plan_id: "browser-plan",
    plan_version: 1,
    image_name: imageName,
    image_sha256: "0".repeat(64),
    event,
    labels,
  };
  const entryJson = JSON.stringify(entry);
  const prevHashHex = vm && vm.auditChain.length > 0 ? vm.prevHashHex : GENESIS_HASH_HEX;
  const outcome = JSON.parse(seal(entryJson, prevHashHex, demo_signing_key_hex()));
  if (!outcome.ok) {
    console.error("audit seal failed:", outcome.error);
    return null;
  }
  const envelopeJson = outcome.envelope;
  const envelopeBytes = new TextEncoder().encode(envelopeJson);
  const nextHash = hash_line(envelopeBytes);
  if (vm) {
    vm.auditChain.push(envelopeJson);
    vm.prevHashHex = bytesToHex(nextHash);
    self.postMessage({ type: "audit", auditChain: vm.auditChain.slice() });
  }
  return envelopeJson;
}

async function launchVm(configJson) {
  if (vm) {
    throw new Error("a microVM is already running; stop it first");
  }

  const config = JSON.parse(configJson);
  const vmId = `vm-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

  const policyJson = JSON.stringify(config.network_policy ?? { type: "deny_all" });
  const authority = config.authority ?? "";
  const name = config.name ?? "browser-vm";

  // Validate that the policy is parseable by the wasm core.
  const validation = JSON.parse(validate_network_policy(policyJson));
  if (!validation.ok) {
    throw new Error(`invalid NetworkPolicy: ${validation.error}`);
  }

  const response = await fetch("./guest/mvm-demo-guest.wasm");
  if (!response.ok) {
    throw new Error(`failed to load guest wasm: ${response.status}`);
  }
  const bytes = await response.arrayBuffer();

  let memory = null;
  const consoleBuffer = [];

  function log(line) {
    consoleBuffer.push(line);
    self.postMessage({ type: "console", vmId, chunk: line });
  }

  function readString(ptr, len) {
    const view = new Uint8Array(memory.buffer, ptr, len);
    return new TextDecoder().decode(view);
  }

  function writeString(ptr, cap, text) {
    const encoded = new TextEncoder().encode(text);
    if (encoded.length > cap) {
      return -1;
    }
    const view = new Uint8Array(memory.buffer, ptr, cap);
    view.set(encoded);
    return encoded.length;
  }

  function readBytes(ptr, len) {
    return new Uint8Array(memory.buffer, ptr, len);
  }

  function writeBytes(ptr, bytes) {
    const view = new Uint8Array(memory.buffer, ptr, bytes.length);
    view.set(bytes);
  }

  // Virtual rootfs.
  const policyBytes = new TextEncoder().encode(policyJson);
  const authorityBytes = new TextEncoder().encode(authority);
  const fsRoot = {
    type: "dir",
    entries: {
      etc: {
        type: "dir",
        entries: {
          policy: { type: "file", data: policyBytes },
          authority: { type: "file", data: authorityBytes },
        },
      },
      bin: {
        type: "dir",
        entries: {
          init: { type: "file", data: new Uint8Array() },
        },
      },
      tmp: {
        type: "dir",
        entries: {},
      },
    },
  };

  function resolvePath(path) {
    const parts = path.split("/").filter((p) => p.length > 0 && p !== ".");
    let node = fsRoot;
    for (const part of parts) {
      if (node.type !== "dir" || !node.entries[part]) {
        return null;
      }
      node = node.entries[part];
    }
    return node;
  }

  // File descriptor table.
  // 0=stdin, 1=stdout, 2=stderr, 3=preopen /
  const fds = [
    { type: "stdin" },
    { type: "stdout" },
    { type: "stderr" },
    { type: "dir", node: fsRoot, path: "/" },
  ];

  function fdValid(fd) {
    return fd >= 0 && fd < fds.length && fds[fd] !== null;
  }

  // WASI errno constants we use.
  const ESUCCESS = 0;
  const E2BIG = 1;
  const EACCES = 2;
  const EBADF = 8;
  const ENOENT = 44;
  const ENOTDIR = 54;
  const EINVAL = 28;
  const EIO = 29;

  function wasi_fd_write(fd, iovsPtr, iovsLen, nwrittenPtr) {
    if (!fdValid(fd)) return EBADF;
    const fdObj = fds[fd];
    if (fdObj.type !== "stdout" && fdObj.type !== "stderr") return EBADF;

    let total = 0;
    const chunks = [];
    for (let i = 0; i < iovsLen; i++) {
      const base = new DataView(memory.buffer).getUint32(iovsPtr + i * 8, true);
      const len = new DataView(memory.buffer).getUint32(iovsPtr + i * 8 + 4, true);
      const bytes = new Uint8Array(memory.buffer, base, len);
      chunks.push(new TextDecoder().decode(bytes));
      total += len;
    }
    const text = chunks.join("");
    // Append to console buffer, preserving line-by-line output.
    const lines = text.split("\n");
    let pending = consoleBuffer.length > 0 ? consoleBuffer.pop() : "";
    for (let i = 0; i < lines.length; i++) {
      pending += lines[i];
      if (i < lines.length - 1) {
        log(pending);
        pending = "";
      }
    }
    if (pending.length > 0 || text.endsWith("\n")) {
      consoleBuffer.push(pending);
    }
    new DataView(memory.buffer).setUint32(nwrittenPtr, total, true);
    return ESUCCESS;
  }

  function wasi_fd_read(fd, iovsPtr, iovsLen, nreadPtr) {
    if (!fdValid(fd)) return EBADF;
    const fdObj = fds[fd];
    if (fdObj.type !== "file") return EBADF;

    let total = 0;
    const file = fdObj.node;
    for (let i = 0; i < iovsLen; i++) {
      const base = new DataView(memory.buffer).getUint32(iovsPtr + i * 8, true);
      const len = new DataView(memory.buffer).getUint32(iovsPtr + i * 8 + 4, true);
      const remaining = file.data.length - fdObj.offset;
      const toRead = Math.min(len, remaining);
      const view = new Uint8Array(memory.buffer, base, toRead);
      view.set(file.data.subarray(fdObj.offset, fdObj.offset + toRead));
      fdObj.offset += toRead;
      total += toRead;
    }
    new DataView(memory.buffer).setUint32(nreadPtr, total, true);
    return ESUCCESS;
  }

  function wasi_fd_prestat_get(fd, prestatPtr) {
    if (!fdValid(fd)) return EBADF;
    const fdObj = fds[fd];
    if (fdObj.type !== "dir") return EBADF;
    const view = new DataView(memory.buffer);
    view.setUint8(prestatPtr, 0); // prestat_dir
    view.setUint32(prestatPtr + 4, fdObj.path.length, true);
    return ESUCCESS;
  }

  function wasi_fd_prestat_dir_name(fd, pathPtr, pathLen) {
    if (!fdValid(fd)) return EBADF;
    const fdObj = fds[fd];
    if (fdObj.type !== "dir") return EBADF;
    const encoded = new TextEncoder().encode(fdObj.path);
    if (encoded.length > pathLen) return E2BIG;
    const view = new Uint8Array(memory.buffer, pathPtr, pathLen);
    view.set(encoded);
    return ESUCCESS;
  }

  function wasi_fd_fdstat_get(fd, fdstatPtr) {
    if (!fdValid(fd)) return EBADF;
    const fdObj = fds[fd];
    const view = new DataView(memory.buffer);
    view.setUint8(fdstatPtr, fdObj.type === "dir" ? 3 : 4); // filetype
    view.setUint16(fdstatPtr + 2, 0, true); // fs_flags
    view.setBigUint64(fdstatPtr + 8, 0n, true); // fs_rights_base
    view.setBigUint64(fdstatPtr + 16, 0n, true); // fs_rights_inheriting
    return ESUCCESS;
  }

  function wasi_path_open(
    dirfd,
    _dirflags,
    pathPtr,
    pathLen,
    _oflags,
    _fsRightsBase,
    _fsRightsInheriting,
    _fdflags,
    openedFdPtr
  ) {
    if (!fdValid(dirfd)) return EBADF;
    const dirObj = fds[dirfd];
    if (dirObj.type !== "dir") return ENOTDIR;

    let relPath = readString(pathPtr, pathLen);
    if (relPath === "" || relPath === ".") {
      relPath = "";
    }
    const fullPath =
      dirObj.path === "/"
        ? (relPath ? `/${relPath}` : "/")
        : (relPath ? `${dirObj.path}/${relPath}` : dirObj.path);
    const node = resolvePath(fullPath);
    if (!node) return ENOENT;
    if (node.type === "dir") {
      fds.push({ type: "dir", node, path: fullPath });
    } else {
      fds.push({ type: "file", node, offset: 0 });
    }
    new DataView(memory.buffer).setUint32(openedFdPtr, fds.length - 1, true);
    return ESUCCESS;
  }

  function wasi_path_filestat_get(
    dirfd,
    _flags,
    pathPtr,
    pathLen,
    filestatPtr
  ) {
    if (!fdValid(dirfd)) return EBADF;
    const dirObj = fds[dirfd];
    if (dirObj.type !== "dir") return ENOTDIR;

    let relPath = readString(pathPtr, pathLen);
    if (relPath === "" || relPath === ".") {
      relPath = "";
    }
    const fullPath =
      dirObj.path === "/"
        ? (relPath ? `/${relPath}` : "/")
        : (relPath ? `${dirObj.path}/${relPath}` : dirObj.path);
    const node = resolvePath(fullPath);
    if (!node) return ENOENT;

    const view = new DataView(memory.buffer);
    view.setBigUint64(filestatPtr, 0n, true); // dev
    view.setBigUint64(filestatPtr + 8, 0n, true); // ino
    view.setUint8(filestatPtr + 16, node.type === "dir" ? 3 : 4); // filetype
    view.setBigUint64(filestatPtr + 24, 0n, true); // nlink
    view.setBigUint64(filestatPtr + 32, BigInt(node.type === "file" ? node.data.length : 0), true); // size
    view.setBigUint64(filestatPtr + 40, 0n, true); // atim
    view.setBigUint64(filestatPtr + 48, 0n, true); // mtim
    view.setBigUint64(filestatPtr + 56, 0n, true); // ctim
    return ESUCCESS;
  }

  function wasi_fd_close(fd) {
    if (!fdValid(fd)) return EBADF;
    fds[fd] = null;
    return ESUCCESS;
  }

  function wasi_fd_seek(fd, offset_low, offset_high, whence, newOffsetPtr) {
    if (!fdValid(fd)) return EBADF;
    const fdObj = fds[fd];
    if (fdObj.type !== "file") return EBADF;
    const offset = (BigInt.asUintN(32, BigInt(offset_high)) << 32n) | BigInt.asUintN(32, BigInt(offset_low));
    const len = BigInt(fdObj.node.data.length);
    let newOffset;
    switch (whence) {
      case 0:
        newOffset = offset;
        break; // SET
      case 1:
        newOffset = BigInt(fdObj.offset) + offset;
        break; // CUR
      case 2:
        newOffset = len + offset;
        break; // END
      default:
        return EINVAL;
    }
    if (newOffset < 0n) newOffset = 0n;
    if (newOffset > len) newOffset = len;
    fdObj.offset = Number(newOffset);
    new DataView(memory.buffer).setBigUint64(newOffsetPtr, newOffset, true);
    return ESUCCESS;
  }

  function wasi_fd_filestat_get(fd, filestatPtr) {
    if (!fdValid(fd)) return EBADF;
    const fdObj = fds[fd];
    const view = new DataView(memory.buffer);
    view.setBigUint64(filestatPtr, 0n, true); // dev
    view.setBigUint64(filestatPtr + 8, 0n, true); // ino
    view.setUint8(filestatPtr + 16, fdObj.type === "dir" ? 3 : 4); // filetype
    view.setBigUint64(filestatPtr + 24, 0n, true); // nlink
    view.setBigUint64(filestatPtr + 32, BigInt(fdObj.type === "file" ? fdObj.node.data.length : 0), true); // size
    view.setBigUint64(filestatPtr + 40, 0n, true); // atim
    view.setBigUint64(filestatPtr + 48, 0n, true); // mtim
    view.setBigUint64(filestatPtr + 56, 0n, true); // ctim
    return ESUCCESS;
  }

  function wasi_fd_readdir(fd, bufPtr, bufLen, _cookie, bufusedPtr) {
    if (!fdValid(fd)) return EBADF;
    const fdObj = fds[fd];
    if (fdObj.type !== "dir") return ENOTDIR;

    const entries = Object.entries(fdObj.node.entries);
    const encoder = new TextEncoder();
    let offset = 0;
    for (let i = 0; i < entries.length; i++) {
      const [name, child] = entries[i];
      const nameBytes = encoder.encode(name);
      const direntSize = 24 + nameBytes.length;
      if (offset + direntSize > bufLen) break;

      const view = new DataView(memory.buffer);
      view.setBigUint64(bufPtr + offset, BigInt(i + 1), true); // d_next
      view.setBigUint64(bufPtr + offset + 8, 0n, true); // d_ino
      view.setUint32(bufPtr + offset + 16, nameBytes.length, true); // d_namlen
      view.setUint8(bufPtr + offset + 20, child.type === "dir" ? 3 : 4); // d_type
      const nameView = new Uint8Array(memory.buffer, bufPtr + offset + 24, nameBytes.length);
      nameView.set(nameBytes);
      offset += direntSize;
    }
    new DataView(memory.buffer).setUint32(bufusedPtr, offset, true);
    return ESUCCESS;
  }

  function wasi_args_get(argvPtr, argvBufPtr) {
    const args = ["init", "--name", name, "--policy", policyJson];
    const encoder = new TextEncoder();
    let bufOffset = 0;
    const view32 = new Uint32Array(memory.buffer);
    const view8 = new Uint8Array(memory.buffer);
    for (let i = 0; i < args.length; i++) {
      const encoded = encoder.encode(args[i] + "\0");
      view32[argvPtr / 4 + i] = argvBufPtr + bufOffset;
      view8.set(encoded, argvBufPtr + bufOffset);
      bufOffset += encoded.length;
    }
    return ESUCCESS;
  }

  function wasi_args_sizes_get(argcPtr, argvBufSizePtr) {
    const args = ["init", "--name", name, "--policy", policyJson];
    const size = args.reduce((acc, a) => acc + a.length + 1, 0);
    const view = new DataView(memory.buffer);
    view.setUint32(argcPtr, args.length, true);
    view.setUint32(argvBufSizePtr, size, true);
    return ESUCCESS;
  }

  function wasi_environ_get(environPtr, environBufPtr) {
    const env = [];
    const encoder = new TextEncoder();
    let bufOffset = 0;
    const view32 = new Uint32Array(memory.buffer);
    const view8 = new Uint8Array(memory.buffer);
    for (let i = 0; i < env.length; i++) {
      const encoded = encoder.encode(env[i] + "\0");
      view32[environPtr / 4 + i] = environBufPtr + bufOffset;
      view8.set(encoded, environBufPtr + bufOffset);
      bufOffset += encoded.length;
    }
    return ESUCCESS;
  }

  function wasi_environ_sizes_get(environCountPtr, environBufSizePtr) {
    const view = new DataView(memory.buffer);
    view.setUint32(environCountPtr, 0, true);
    view.setUint32(environBufSizePtr, 0, true);
    return ESUCCESS;
  }

  function wasi_clock_time_get(id, precision, timePtr) {
    const now = BigInt(Date.now()) * 1_000_000n;
    new DataView(memory.buffer).setBigUint64(timePtr, now, true);
    return ESUCCESS;
  }

  function wasi_proc_exit(code) {
    throw new ExitError(code);
  }

  function mvmEgress(hostPtr, hostLen, port, bodyPtr, bodyLen, outPtr, outCap) {
    const host = readString(hostPtr, hostLen);
    const body = readBytes(bodyPtr, bodyLen);
    const url = `https://${host}:${port}/`;

    const decision = JSON.parse(decide_egress(policyJson, url));
    if (!decision.ok) {
      const msg = `policy error: ${decision.error}`;
      const n = writeString(outPtr, outCap, msg);
      return n < 0 ? -5 : n;
    }
    if (!decision.allowed) {
        signAuditEntry("egress.deny", vm.imageName, { host, port: port.toString() });
      return -13; // EACCES
    }
    signAuditEntry("egress.allow", vm.imageName, { host, port: port.toString() });

    // The policy allowed the egress. Attempt a real synchronous fetch so the
    // guest sees an actual network result, but fall back to a mock response
    // when CORS or the browser sandbox blocks it.
    try {
      const xhr = new XMLHttpRequest();
      xhr.open(bodyLen > 0 ? "POST" : "GET", url, false);
      if (bodyLen > 0) {
        xhr.send(body);
      } else {
        xhr.send();
      }
      const text = `status: ${xhr.status}
${xhr.responseText}`;
      const n = writeString(outPtr, outCap, text);
      return n < 0 ? -5 : n;
    } catch (err) {
      const text = `policy allowed, but browser blocked the fetch: ${err.message}`;
      const n = writeString(outPtr, outCap, text);
      return n < 0 ? -5 : n;
    }
  }

  const module = await WebAssembly.instantiate(bytes, {
    wasi_snapshot_preview1: {
      args_get: wasi_args_get,
      args_sizes_get: wasi_args_sizes_get,
      environ_get: wasi_environ_get,
      environ_sizes_get: wasi_environ_sizes_get,
      clock_time_get: wasi_clock_time_get,
      fd_write: wasi_fd_write,
      fd_read: wasi_fd_read,
      fd_prestat_get: wasi_fd_prestat_get,
      fd_prestat_dir_name: wasi_fd_prestat_dir_name,
      fd_fdstat_get: wasi_fd_fdstat_get,
      fd_close: wasi_fd_close,
      path_open: wasi_path_open,
      path_filestat_get: wasi_path_filestat_get,
      fd_seek: wasi_fd_seek,
      fd_filestat_get: wasi_fd_filestat_get,
      fd_readdir: wasi_fd_readdir,
      proc_exit: wasi_proc_exit,
      poll_oneoff: () => ESUCCESS, // stdin is not used; stub.
    },
    mvm: { egress: mvmEgress },
  });

  const instance = module.instance;
  memory = instance.exports.memory;
  vm = {
    vmId,
    instance,
    memory,
    consoleBuffer,
    policyJson,
    status: "running",
    auditChain: [],
    prevHashHex: GENESIS_HASH_HEX,
    imageName: config.image || "mvm-demo-guest:latest",
  };

  signAuditEntry("vm.start", vm.imageName, { vm_id: vmId });

  // Run init() to print boot sequence and first prompt.
  try {
    instance.exports.init();
  } catch (err) {
    if (err instanceof ExitError) {
      vm.status = "exited";
    } else {
      throw err;
    }
  }

  return { vmId, status: vm.status, auditChain: vm.auditChain };
}

async function sendStdin(line) {
  if (!vm) {
    throw new Error("no microVM is running");
  }
  if (vm.status !== "running") {
    throw new Error(`microVM is ${vm.status}`);
  }

  const encoder = new TextEncoder();
  const bytes = encoder.encode(line);
  const ptr = vm.instance.exports.command_buffer_ptr
    ? vm.instance.exports.command_buffer_ptr()
    : null;
  const bufLen = vm.instance.exports.command_buffer_len();
  if (bytes.length > bufLen) {
    throw new Error(`command too long: ${bytes.length} > ${bufLen}`);
  }
  if (ptr === null) {
    throw new Error("guest does not export command_buffer_ptr; cannot send command");
  }

  writeBytes(vm.memory, ptr, bytes);
  vm.instance.exports.exec(ptr, bytes.length);

  return { status: vm.status };
}

function stopVm() {
  if (!vm) {
    return { status: "stopped" };
  }
  signAuditEntry("vm.stop", vm.imageName, { vm_id: vm.vmId });
  vm.status = "stopped";
  const id = vm.vmId;
  const chain = vm.auditChain;
  vm = null;
  return { vmId: id, status: "stopped", auditChain: chain };
}

function getLogs(lines) {
  if (!vm) {
    return { lines: [], auditChain: [] };
  }
  const start = Math.max(0, vm.consoleBuffer.length - (lines ?? 100));
  return { lines: vm.consoleBuffer.slice(start), auditChain: vm.auditChain };
}

function getStatus() {
  if (!vm) {
    return { status: "stopped" };
  }
  return { vmId: vm.vmId, status: vm.status };
}

class ExitError extends Error {
  constructor(code) {
    super(`proc_exit(${code})`);
    this.code = code;
  }
}

function writeBytes(memory, ptr, bytes) {
  const view = new Uint8Array(memory.buffer, ptr, bytes.length);
  view.set(bytes);
}
