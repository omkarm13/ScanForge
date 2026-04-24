import React, { useEffect, useState } from "react";
import SectionTitle from "../components/SectionTitle.jsx";
import { fetchHistory } from "../api/scans.js";

export default function MisconfigPage() {
  const [misconfigs, setMisconfigs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const loadMisconfigs = async () => {
    setLoading(true);
    setError("");
    try {
      const data = await fetchHistory();
      const extracted = [];
      data.forEach((scan) => {
        if (scan.corsResult) {
          Object.entries(scan.corsResult).forEach(([host, ports]) => {
            Object.entries(ports).forEach(([port, cors]) => {
              if (cors.vulnerable) {
                extracted.push({
                  scanId: scan._id,
                  date: new Date(scan.createdAt).toLocaleString(),
                  host,
                  port,
                  acao: cors.acao,
                  acac: cors.acac
                });
              }
            });
          });
        }
      });
      setMisconfigs(extracted);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadMisconfigs();
  }, []);

  return (
    <div className="page-content">
      <section className="history">
        <div className="history-header">
          <SectionTitle
            kicker="Misconfigurations"
            title="CORS Vulnerabilities"
            desc="List of targets exhibiting CORS misconfigurations across all historical scans."
          />
          <button className="ghost" onClick={loadMisconfigs} disabled={loading}>
            {loading ? "Refreshing..." : "Refresh"}
          </button>
        </div>
        {error ? <div className="error">{error}</div> : null}
        
        <div className="card" style={{ marginTop: "24px", padding: "24px" }}>
          {misconfigs.length === 0 && !loading ? (
            <div className="muted">No CORS misconfigurations found in scan history.</div>
          ) : (
            <div className="misconfig-list">
              {misconfigs.map((m, idx) => (
                <div key={`${m.scanId}-${m.host}-${m.port}-${idx}`} className="host-card" style={{ marginBottom: "16px" }}>
                  <div className="history-title-row" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div className="host-title" style={{ margin: 0 }}>{m.host}:{m.port}</div>
                    <span className="muted">{m.date}</span>
                  </div>
                  <div className="cors-alerts" style={{ marginTop: "12px" }}>
                    <div className="cors-alert" style={{ display: 'flex', alignItems: 'center' }}>
                      <span className="status-pill failed" style={{ background: "rgba(220, 38, 38, 0.2)", color: "#fca5a5" }}>
                        CORS Misconfigured
                      </span>
                      <span className="muted" style={{ marginLeft: "12px", fontSize: "14px" }}>
                        Access-Control-Allow-Origin: <strong style={{ color: "var(--fg)" }}>{m.acao || "not set"}</strong>
                      </span>
                      {m.acac && (
                         <span className="muted" style={{ marginLeft: "8px", fontSize: "14px" }}>
                          | Credentials: <strong style={{ color: "var(--fg)" }}>{m.acac}</strong>
                         </span>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
