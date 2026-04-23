import React from "react";
import BannerBlock from "./BannerBlock.jsx";
import CveList from "./CveList.jsx";
import SectionTitle from "./SectionTitle.jsx";

export default function ScanResults({ scan, loading }) {
  if (!scan) {
    if (loading) {
      return (
        <div className="results">
          <div className="status-pill running">running</div>
          <div className="muted">Scan in progress. Results will appear here as they stream in.</div>
        </div>
      );
    }
    return <div className="muted">No scan yet. Run one to see results.</div>;
  }

  return (
    <div className="results">
      <div className="result-meta">
        <div>
          <span>Targets</span>
          <strong>{scan.stats?.targets || 0}</strong>
        </div>
        <div>
          <span>Live</span>
          <strong>{scan.stats?.liveTargets || 0}</strong>
        </div>
        <div>
          <span>Ports</span>
          <strong>{scan.stats?.ports || 0}</strong>
        </div>
      </div>
      <div className={`status-pill ${scan.status || "queued"}`}>{scan.status || "queued"}</div>
      {loading ? <div className="muted">Scan running. Updating results...</div> : null}
      {scan.status === "failed" ? (
        <div className="error">Scan failed: {scan.stats?.error || "Unknown error"}</div>
      ) : null}
      <div className="scan-block">
        {Object.entries(scan.scanResult || {}).map(([host, portsList]) => (
          <div key={host} className="host-card">
            <div className="host-title">{host}</div>
            <div className="host-ports">Ports: {portsList.join(", ") || "none"}</div>
            <BannerBlock banners={scan.banners ? scan.banners[host] : null} />
          </div>
        ))}
      </div>
      <div className="scan-block">
        <SectionTitle kicker="Shodan" title="CVE Findings" desc="Aggregated CVEs across targets." />
        <CveList shodan={scan.shodanResult} />
      </div>
      {scan?._id ? (
        <div className="export-row">
          <a href={`/api/scans/${scan._id}/export?format=json`} target="_blank" rel="noreferrer">
            Export JSON
          </a>
          <a href={`/api/scans/${scan._id}/export?format=csv`} target="_blank" rel="noreferrer">
            Export CSV
          </a>
        </div>
      ) : null}
    </div>
  );
}
