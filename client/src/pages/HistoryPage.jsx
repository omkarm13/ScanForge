import React, { useEffect, useState } from "react";
import ScanResults from "../components/ScanResults.jsx";
import SectionTitle from "../components/SectionTitle.jsx";
import { fetchHistory } from "../api/scans.js";

export default function HistoryPage() {
  const [history, setHistory] = useState([]);
  const [activeScan, setActiveScan] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const loadHistory = async () => {
    setLoading(true);
    setError("");
    try {
      const data = await fetchHistory();
      setHistory(data);
      if (!activeScan && data.length) {
        setActiveScan(data[0]);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadHistory();
  }, []);

  return (
    <div className="page-content">
      <section className="history">
        <div className="history-header">
          <SectionTitle
            kicker="History"
            title="Previous Scans"
            desc="Most recent 100 scans saved with timestamps."
          />
          <button className="ghost" onClick={loadHistory} disabled={loading}>
            {loading ? "Refreshing..." : "Refresh History"}
          </button>
        </div>
        {error ? <div className="error">{error}</div> : null}
        <div className="history-layout">
          <div className="history-list">
            <div className="history-list-header">
              <span>Recent scans</span>
              <span className="muted">{history.length}</span>
            </div>
            {history.length ? (
              <div className="history-grid">
                {history.map((scan) => (
                  <button
                    key={scan._id}
                    className={`history-card ${activeScan?._id === scan._id ? "selected" : ""}`}
                    onClick={() => setActiveScan(scan)}
                  >
                    <div className="history-title-row">
                      <div className="history-title">{new Date(scan.createdAt).toLocaleString()}</div>
                      <span className={`status-pill ${scan.status || "queued"}`}>{scan.status || "queued"}</span>
                    </div>
                    <div className="history-meta">
                      <span>{scan.stats?.targets || 0} targets</span>
                      <span>{scan.stats?.ports || 0} ports</span>
                      <span>{scan.stats?.liveTargets || 0} live</span>
                    </div>
                  </button>
                ))}
              </div>
            ) : (
              <div className="muted">No scans yet. Run a scan to populate history.</div>
            )}
          </div>
          <div className="history-details card">
            <SectionTitle kicker="Selected" title="Scan Details" desc="Full result set for the chosen scan." />
            <ScanResults scan={activeScan} />
          </div>
        </div>
      </section>
    </div>
  );
}
