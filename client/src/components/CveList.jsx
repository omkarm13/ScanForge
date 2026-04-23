import React from "react";

export default function CveList({ shodan }) {
  if (shodan && shodan.error) {
    return <div className="error">Shodan: {shodan.error}</div>;
  }
  const entries = Object.entries(shodan || {});
  if (!entries.length) return <div className="muted">No CVEs found</div>;
  return (
    <div className="cve-list">
      {entries.map(([cve, data]) => (
        <div className="cve-card" key={cve}>
          <div className="cve-title">{cve}</div>
          <div className="cve-links">
            <a href={data.mitre} target="_blank" rel="noreferrer">
              MITRE
            </a>
            <a href={data.nvd} target="_blank" rel="noreferrer">
              NVD
            </a>
          </div>
          <div className="cve-meta">
            <span>CVSS: {data.cvss?.length ? data.cvss.join(", ") : "n/a"}</span>
          </div>
          <div className="cve-ips">{data.ips?.join(", ")}</div>
        </div>
      ))}
    </div>
  );
}
