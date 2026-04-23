import https from "https";
import dotenv from "dotenv";

dotenv.config();

const shodanKey = process.env.SHODAN_API_KEY || "";
const nvdKey = process.env.NVD_API_KEY || "";

const fetchJson = (url, headers = {}) =>
  new Promise((resolve, reject) => {
    https
      .get(url, { headers }, (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          try {
            resolve(JSON.parse(data));
          } catch (err) {
            const snippet = String(data).trim().slice(0, 200);
            resolve({
              error: `Non-JSON response (${res.statusCode || "unknown"}): ${snippet || "empty"}`,
            });
          }
        });
      })
      .on("error", reject);
  });

const shodanHost = async (ip, rateLimit) => {
  const url = `https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(shodanKey)}`;
  const data = await fetchJson(url);
  if (data && data.error) {
    throw new Error(data.error);
  }
  if (rateLimit) await new Promise((r) => setTimeout(r, rateLimit * 1000));
  return data;
};

const shodanSearch = async (query, page, rateLimit) => {
  const url = `https://api.shodan.io/shodan/host/search?key=${encodeURIComponent(shodanKey)}&query=${encodeURIComponent(query)}&page=${page}`;
  const data = await fetchJson(url);
  if (data && data.error) {
    throw new Error(data.error);
  }
  if (rateLimit) await new Promise((r) => setTimeout(r, rateLimit * 1000));
  return data;
};

const collectCves = (vulns) => {
  if (!vulns) return [];
  if (Array.isArray(vulns)) return vulns.filter((v) => typeof v === "string" && v.startsWith("CVE-"));
  if (typeof vulns === "object") return Object.keys(vulns).filter((v) => v.startsWith("CVE-"));
  return [];
};

const extractCvss = (vulns) => {
  const scores = {};
  if (vulns && typeof vulns === "object" && !Array.isArray(vulns)) {
    for (const [cve, info] of Object.entries(vulns)) {
      if (!cve.startsWith("CVE-")) continue;
      if (info && typeof info === "object" && "cvss" in info) {
        const val = Number(info.cvss);
        if (!Number.isNaN(val)) scores[cve] = val;
      } else if (typeof info === "number") {
        scores[cve] = info;
      }
    }
  }
  return scores;
};

const cveLinks = (cve) => ({
  mitre: `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve}`,
  nvd: `https://nvd.nist.gov/vuln/detail/${cve}`,
});

const fetchNvdCvss = async (cve) => {
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cve)}`;
  const headers = nvdKey ? { "apiKey": nvdKey } : {};
  const data = await fetchJson(url, headers);
  const item = data?.vulnerabilities?.[0]?.cve;
  const metrics = item?.metrics || {};
  const v31 = metrics.cvssMetricV31?.[0]?.cvssData?.baseScore;
  const v30 = metrics.cvssMetricV30?.[0]?.cvssData?.baseScore;
  const v2 = metrics.cvssMetricV2?.[0]?.cvssData?.baseScore;
  return v31 || v30 || v2 || null;
};

const mergeCves = (map, cvssMap, ip, vulns) => {
  const cves = collectCves(vulns);
  const cvss = extractCvss(vulns);
  for (const cve of cves) {
    if (!map[cve]) map[cve] = new Set();
    map[cve].add(ip);
  }
  for (const [cve, score] of Object.entries(cvss)) {
    if (!cvssMap[cve]) cvssMap[cve] = new Set();
    cvssMap[cve].add(score);
  }
};

export const shodanLookup = async (targets, options) => {
  if (!shodanKey) return { error: "SHODAN_API_KEY not set" };
  const cveMap = {};
  const cvssMap = {};
  const limit = options.limit || 0;
  const rateLimit = options.rateLimit || 1;

  const handleHost = async (ip) => {
    const data = await shodanHost(ip, rateLimit);
    mergeCves(cveMap, cvssMap, ip, data.vulns);
  };

  const handleSearch = async (query) => {
    let page = 1;
    let seen = 0;
    while (true) {
      const data = await shodanSearch(query, page, rateLimit);
      const matches = data.matches || [];
      if (!matches.length) break;
      for (const match of matches) {
        const ip = match.ip_str || match.ip;
        if (!ip) continue;
        mergeCves(cveMap, cvssMap, ip, match.vulns);
        seen += 1;
        if (limit && seen >= limit) return;
      }
      page += 1;
    }
  };

  for (const target of targets) {
    if (target.type === "ip") {
      await handleHost(target.value);
    } else if (target.type === "cidr") {
      await handleSearch(`net:${target.value}`);
    } else if (target.type === "domain") {
      await handleSearch(`hostname:${target.value}`);
    } else if (target.type === "asn") {
      await handleSearch(`asn:${target.value}`);
    }
  }

  const out = {};
  for (const [cve, ips] of Object.entries(cveMap)) {
    out[cve] = {
      ...cveLinks(cve),
      ips: Array.from(ips).sort(),
      cvss: Array.from(cvssMap[cve] || []).sort(),
    };
  }

  const missing = Object.entries(out)
    .filter(([, data]) => !data.cvss.length)
    .map(([cve]) => cve);

  for (const cve of missing) {
    // eslint-disable-next-line no-await-in-loop
    const score = await fetchNvdCvss(cve);
    if (score) out[cve].cvss = [score];
    // NVD rate limiting (optional)
    await new Promise((r) => setTimeout(r, nvdKey ? 600 : 1200));
  }

  return out;
};
