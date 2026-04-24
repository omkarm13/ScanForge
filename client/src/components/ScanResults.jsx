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
            {(() => {
              const hasCorsData = scan.corsResult && scan.corsResult[host] && Object.keys(scan.corsResult[host]).length > 0;
              const corsChecked = scan.input?.corsEnabled;
              
              if (hasCorsData) {
                return (
                  <div className="cors-alerts" style={{ marginTop: "8px", marginBottom: "8px" }}>
                    {Object.entries(scan.corsResult[host]).map(([port, cors]) => (
                      <div key={port} className="cors-alert">
                        <span className="status-pill failed" style={{ background: "rgba(220, 38, 38, 0.2)", color: "#fca5a5" }}>CORS Misconfigured on {port}</span>
                        <span className="muted" style={{ marginLeft: "8px", fontSize: "12px" }}>ACAO: {cors.acao || "not set"}</span>
                      </div>
                    ))}
                  </div>
                );
              } else if (corsChecked) {
                return (
                  <div className="cors-alerts" style={{ marginTop: "8px", marginBottom: "8px" }}>
                    <div className="cors-alert">
                      <span className="status-pill success" style={{ background: "rgba(34, 197, 94, 0.2)", color: "#86efac" }}>CORS Safe</span>
                      <span className="muted" style={{ marginLeft: "8px", fontSize: "12px" }}>No misconfigurations detected</span>
                    </div>
                  </div>
                );
              }
              return null;
            })()}
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
