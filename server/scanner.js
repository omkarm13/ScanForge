import dns from "dns";
import net from "net";
import { promisify } from "util";
import { execFile } from "child_process";
import IPCIDR from "ip-cidr";
import { shodanLookup } from "./shodan.js";
import dgram from "dgram";
import http from "http";
import https from "https";

const resolve4 = promisify(dns.resolve4);
const resolve6 = promisify(dns.resolve6);

const unique = (arr) => Array.from(new Set(arr));

const parsePorts = (value) => {
  const ports = new Set();
  const parts = String(value || "").split(",");
  for (const part of parts) {
    const p = part.trim();
    if (!p) continue;
    if (p.includes("-")) {
      const [a, b] = p.split("-", 2).map((x) => Number(x));
      if (Number.isNaN(a) || Number.isNaN(b)) continue;
      const start = Math.min(a, b);
      const end = Math.max(a, b);
      for (let i = start; i <= end; i += 1) {
        if (i >= 1 && i <= 65535) ports.add(i);
      }
    } else {
      const n = Number(p);
      if (!Number.isNaN(n) && n >= 1 && n <= 65535) ports.add(n);
    }
  }
  return Array.from(ports).sort((a, b) => a - b);
};

const decodeEscapes = (value) =>
  String(value || "")
    .replace(/\\r/g, "\r")
    .replace(/\\n/g, "\n")
    .replace(/\\t/g, "\t");

const HTTP_PROBE_PORTS = new Set([80, 8080, 8000, 8181, 8888, 8081, 3000]);

const getTcpProbe = (port, fallback) => {
  if (HTTP_PROBE_PORTS.has(port)) return "HEAD / HTTP/1.0\r\n\r\n";
  return fallback || "";
};

const buildDnsVersionQuery = () => {
  const name = "version.bind";
  const labels = name.split(".");
  const qname = labels
    .map((l) => {
      const buf = Buffer.alloc(1 + l.length);
      buf.writeUInt8(l.length, 0);
      buf.write(l, 1);
      return buf;
    })
    .reduce((acc, b) => Buffer.concat([acc, b]), Buffer.alloc(0));

  const header = Buffer.alloc(12);
  header.writeUInt16BE(0x1234, 0); // id
  header.writeUInt16BE(0x0100, 2); // recursion desired
  header.writeUInt16BE(1, 4); // qdcount

  const qtype = Buffer.alloc(2);
  qtype.writeUInt16BE(16, 0); // TXT
  const qclass = Buffer.alloc(2);
  qclass.writeUInt16BE(3, 0); // CH (CHAOS)

  return Buffer.concat([header, qname, Buffer.from([0x00]), qtype, qclass]);
};

const parseDnsTxt = (buf) => {
  try {
    const qd = buf.readUInt16BE(4);
    const an = buf.readUInt16BE(6);
    let offset = 12;
    const skipName = () => {
      while (offset < buf.length) {
        const len = buf.readUInt8(offset);
        if (len === 0) {
          offset += 1;
          return;
        }
        if ((len & 0xc0) === 0xc0) {
          offset += 2;
          return;
        }
        offset += 1 + len;
      }
    };
    for (let i = 0; i < qd; i += 1) {
      skipName();
      offset += 4;
    }
    const texts = [];
    for (let i = 0; i < an; i += 1) {
      skipName();
      const type = buf.readUInt16BE(offset);
      offset += 2;
      offset += 2; // class
      offset += 4; // ttl
      const rdlen = buf.readUInt16BE(offset);
      offset += 2;
      if (type === 16) {
        const end = offset + rdlen;
        while (offset < end) {
          const l = buf.readUInt8(offset);
          offset += 1;
          const txt = buf.slice(offset, offset + l).toString("utf-8");
          offset += l;
          texts.push(txt);
        }
      } else {
        offset += rdlen;
      }
    }
    return texts.join(" ").trim();
  } catch {
    return "";
  }
};

const isIp = (value) => net.isIP(value) !== 0;

const resolveDomain = async (domain) => {
  const out = [];
  try {
    out.push(...(await resolve4(domain)));
  } catch {}
  try {
    out.push(...(await resolve6(domain)));
  } catch {}
  return unique(out);
};

const expandCidr = (cidr) => {
  const block = new IPCIDR(cidr);
  if (!block.isValid()) return [];
  return block.toArray({ type: "addressObject" }).map((r) => r.address);
};

const expandAsn = async (asn) =>
  new Promise((resolve, reject) => {
    const normalized = String(asn).toUpperCase().startsWith("AS")
      ? String(asn).toUpperCase()
      : `AS${asn}`;
    execFile("asnmap", ["-a", normalized], (err, stdout, stderr) => {
      if (err) {
        const msg = stderr?.trim() || err.message || "asnmap failed";
        reject(new Error(msg));
        return;
      }
      const prefixes = String(stdout)
        .split(/\r?\n/)
        .map((x) => x.trim())
        .filter(Boolean);
      const ips = [];
      for (const prefix of prefixes) {
        const block = new IPCIDR(prefix);
        if (!block.isValid()) continue;
        ips.push(...block.toArray({ type: "addressObject" }).map((r) => r.address));
      }
      resolve(ips);
    });
  });

const parseTargets = (config) => {
  const targets = [];
  const push = (type, value) => {
    if (!value) return;
    targets.push({ type, value });
  };
  if (config.ip) push("ip", config.ip);
  if (config.cidr) push("cidr", config.cidr);
  if (config.domain) push("domain", config.domain);
  if (Array.isArray(config.domains)) config.domains.forEach((d) => push("domain", d));
  if (Array.isArray(config.asn)) config.asn.forEach((a) => push("asn", a));
  if (config.asn && !Array.isArray(config.asn)) push("asn", config.asn);
  if (Array.isArray(config.targets)) {
    config.targets.forEach((t) => {
      if (isIp(t)) push("ip", t);
      else if (String(t).includes("/")) push("cidr", t);
      else push("domain", t);
    });
  }
  return targets;
};

const readTextList = (value) => {
  if (!value) return [];
  return String(value)
    .split(/\r?\n/)
    .map((x) => x.trim())
    .filter((x) => x && !x.startsWith("#"));
};

export const resolveTargets = async (config) => {
  const base = parseTargets(config);
  if (config.ipFile) readTextList(config.ipFile).forEach((ip) => base.push({ type: "ip", value: ip }));
  if (config.domainFile) readTextList(config.domainFile).forEach((d) => base.push({ type: "domain", value: d }));
  if (config.targetsFile) {
    readTextList(config.targetsFile).forEach((t) => {
      if (isIp(t)) base.push({ type: "ip", value: t });
      else if (t.includes("/")) base.push({ type: "cidr", value: t });
      else base.push({ type: "domain", value: t });
    });
  }

  const resolved = [];
  for (const t of base) {
    if (t.type === "ip") {
      resolved.push(t.value);
    } else if (t.type === "cidr") {
      resolved.push(...expandCidr(t.value));
    } else if (t.type === "domain") {
      resolved.push(...(await resolveDomain(t.value)));
    } else if (t.type === "asn") {
      resolved.push(...(await expandAsn(t.value)));
    }
  }

  return { targets: unique(resolved), baseTargets: base };
};

const scanPort = (host, port, timeoutMs, bannerTimeoutMs, maxBytes, bannerSend) =>
  new Promise((resolve) => {
    const socket = new net.Socket();
    let data = Buffer.alloc(0);
    let done = false;
    let isOpen = false;
    const finalize = () => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve({ open: isOpen, banner: data.length ? data.toString("utf-8") : "" });
    };
    socket.setTimeout(timeoutMs);
    socket.on("connect", () => {
      isOpen = true;
      if (bannerSend) socket.write(bannerSend);
      socket.setTimeout(bannerTimeoutMs);
    });
    socket.on("data", (chunk) => {
      data = Buffer.concat([data, chunk]);
      if (data.length >= maxBytes) finalize();
    });
    socket.on("timeout", () => finalize());
    socket.on("error", () => finalize());
    socket.on("close", () => finalize());
    socket.connect(port, host);
  });

const scanDnsTcp = (host, port, timeoutMs, bannerTimeoutMs) =>
  new Promise((resolve) => {
    const socket = new net.Socket();
    let data = Buffer.alloc(0);
    let done = false;
    let isOpen = false;
    const finalize = () => {
      if (done) return;
      done = true;
      socket.destroy();
      const text = data.length ? parseDnsTxt(data) : "";
      resolve({ open: isOpen, banner: text });
    };
    socket.setTimeout(timeoutMs);
    socket.on("connect", () => {
      isOpen = true;
      const query = buildDnsVersionQuery();
      const len = Buffer.alloc(2);
      len.writeUInt16BE(query.length, 0);
      socket.write(Buffer.concat([len, query]));
      socket.setTimeout(bannerTimeoutMs);
    });
    socket.on("data", (chunk) => {
      data = Buffer.concat([data, chunk]);
      if (data.length > 2) {
        const msg = data.slice(2);
        finalize();
        data = msg;
      }
    });
    socket.on("timeout", () => finalize());
    socket.on("error", () => finalize());
    socket.on("close", () => finalize());
    socket.connect(port, host);
  });

const scanDnsUdp = (host, port, timeoutMs) =>
  new Promise((resolve) => {
    const socket = dgram.createSocket("udp4");
    const query = buildDnsVersionQuery();
    const timer = setTimeout(() => {
      socket.close();
      resolve("");
    }, timeoutMs);
    socket.on("message", (msg) => {
      clearTimeout(timer);
      socket.close();
      resolve(parseDnsTxt(msg));
    });
    socket.send(query, port, host, (err) => {
      if (err) {
        clearTimeout(timer);
        socket.close();
        resolve("");
      }
    });
  });

const pingHost = (host, timeoutMs) =>
  new Promise((resolve) => {
    if (!isIp(host)) return resolve(false);
    const seconds = Math.max(1, Math.ceil(timeoutMs / 1000));
    execFile("ping", ["-c", "1", "-W", String(seconds), host], (err) => {
      resolve(!err);
    });
  });

const tcpProbe = async (host, ports, timeoutMs) => {
  for (const port of ports) {
    // eslint-disable-next-line no-await-in-loop
    const { open } = await scanPort(host, port, timeoutMs, timeoutMs, 1, "");
    if (open) return true;
  }
  return false;
};

const liveCheck = async (host, ports, timeoutMs) => {
  const pingOk = await pingHost(host, timeoutMs);
  if (pingOk) return true;
  return tcpProbe(host, ports, timeoutMs);
};

const checkCors = (host, port, timeoutMs) => new Promise((resolve) => {
  const isHttps = port === 443 || port === 8443;
  const protocol = isHttps ? https : http;
  const req = protocol.request({
    hostname: host,
    port: port,
    path: '/',
    method: 'GET',
    timeout: timeoutMs,
    rejectUnauthorized: false,
    headers: {
      'Origin': 'https://evil.com'
    }
  }, (res) => {
    const acao = res.headers['access-control-allow-origin'];
    const acac = res.headers['access-control-allow-credentials'];
    if (acao === '*' || acao === 'https://evil.com') {
      resolve({ vulnerable: true, acao, acac });
    } else {
      resolve({ vulnerable: false });
    }
    res.resume();
  });
  
  req.on('timeout', () => { req.destroy(); resolve({ vulnerable: false }); });
  req.on('error', () => resolve({ vulnerable: false }));
  req.end();
});

export const scanTargets = async (config) => {
  const portScanEnabled = config.portScanEnabled !== false;
  const ports = portScanEnabled ? parsePorts(config.ports || "80,443") : [];
  const livePorts = parsePorts(config.livePorts || "22,80,443,53,445,3389");
  const targets = config.targets || [];
  const timeoutMs = Math.max(100, Number(config.timeout || 0.6) * 1000);
  const liveTimeoutMs = Math.max(100, Number(config.liveTimeout || 1.0) * 1000);
  const bannerTimeoutMs = Math.max(100, Number(config.bannerTimeout || 1.0) * 1000);
  const bannerBytes = Number(config.bannerBytes || 1024);
  const bannerSend = decodeEscapes(config.bannerSend || "");
  const noLiveCheck = !!config.noLiveCheck;
  const enableUdp = portScanEnabled && config.enableUdp !== false;
  const udpPorts = parsePorts(config.udpPorts || "53");
  const dnsVersionProbe = config.dnsVersionProbe !== false;
  const corsEnabled = !!config.corsEnabled;

  const liveTargets = [];
  if (!noLiveCheck) {
    for (const host of targets) {
      // eslint-disable-next-line no-await-in-loop
      if (await liveCheck(host, livePorts, liveTimeoutMs)) {
        liveTargets.push(host);
      }
    }
  } else {
    liveTargets.push(...targets);
  }

  const scanResult = {};
  const banners = {};
  const corsResult = {};
  for (const host of liveTargets) {
    scanResult[host] = [];
    banners[host] = {};
    corsResult[host] = {};
    for (const port of ports) {
      // eslint-disable-next-line no-await-in-loop
      const probe = getTcpProbe(port, bannerSend);
      const { open, banner } = port === 53 && dnsVersionProbe
        ? await scanDnsTcp(host, port, timeoutMs, bannerTimeoutMs)
        : await scanPort(host, port, timeoutMs, bannerTimeoutMs, bannerBytes, probe);
      if (open) {
        scanResult[host].push(port);
        if (banner) banners[host][port] = banner;
        
        if (corsEnabled && (HTTP_PROBE_PORTS.has(port) || port === 443 || port === 8443)) {
          // eslint-disable-next-line no-await-in-loop
          const corsData = await checkCors(host, port, bannerTimeoutMs);
          if (corsData.vulnerable) {
            corsResult[host][port] = corsData;
          }
        }
      }
    }
    if (enableUdp) {
      for (const port of udpPorts) {
        if (port !== 53 || !dnsVersionProbe) continue;
        // eslint-disable-next-line no-await-in-loop
        const udpBanner = await scanDnsUdp(host, port, bannerTimeoutMs);
        if (udpBanner) banners[host][`udp:${port}`] = udpBanner;
      }
    }
  }

  const shodanResult =
    config.shodanEnabled === false
      ? {}
      : await shodanLookup(config.shodanTargets || [], {
          limit: config.shodanLimit,
          rateLimit: config.shodanRateLimit,
        });

  return {
    scanResult,
    banners,
    shodanResult,
    corsResult,
    stats: {
      targets: targets.length,
      liveTargets: liveTargets.length,
      ports: ports.length,
    },
  };
};
