import React, { useEffect, useState } from "react";
import SectionTitle from "../components/SectionTitle.jsx";
import { fetchHistory, fetchQueue } from "../api/scans.js";

export default function QueuePage() {
  const [queue, setQueue] = useState({ waiting: 0, active: 0, completed: 0, failed: 0 });
  const [activeScans, setActiveScans] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const getTargetsPreview = (scan) => {
    const targets = scan.input?.targets?.length ? scan.input.targets : scan.resolvedTargets || [];
    if (!targets.length) return "n/a";
    const preview = targets.slice(0, 3).join(", ");
    const more = targets.length > 3 ? ` +${targets.length - 3} more` : "";
    return `${preview}${more}`;
  };

  const getTargetsCount = (scan) =>
    scan.stats?.targets || scan.resolvedTargets?.length || scan.input?.targets?.length || 0;

  const loadQueue = async () => {
    setLoading(true);
    setError("");
    try {
      const [queueData, history] = await Promise.all([fetchQueue(), fetchHistory()]);
      setQueue(queueData);
      const running = history.filter((scan) => scan.status === "running" || scan.status === "queued");
      setActiveScans(running);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadQueue();
  }, []);

  return (
    <div className="page-content">
      <section className="queue">
        <SectionTitle kicker="Queue" title="Job Status" desc="Live view of scan queue health." />
        <div className="queue-grid">
          <div className="queue-card">
            <span>Waiting</span>
            <strong>{queue.waiting}</strong>
          </div>
          <div className="queue-card">
            <span>Active</span>
            <strong>{queue.active}</strong>
          </div>
          <div className="queue-card">
            <span>Completed</span>
            <strong>{queue.completed}</strong>
          </div>
          <div className="queue-card">
            <span>Failed</span>
            <strong>{queue.failed}</strong>
          </div>
        </div>
        <div className="queue-detail">
          <div className="queue-detail-header">
            <span>Active scans</span>
            <span className="muted">{activeScans.length}</span>
          </div>
          {activeScans.length ? (
            <div className="queue-list">
              {activeScans.map((scan) => (
                <div key={scan._id} className="queue-item">
                  <div className="queue-item-main">
                    <div className="queue-item-title">{new Date(scan.createdAt).toLocaleString()}</div>
                    <div className="queue-item-meta">{getTargetsCount(scan)} targets</div>
                    <div className="queue-item-details">
                      <div>
                        <span>Targets</span>
                        <strong>{getTargetsPreview(scan)}</strong>
                      </div>
                      <div>
                        <span>Ports</span>
                        <strong>{scan.input?.ports || "n/a"}</strong>
                      </div>
                      <div>
                        <span>Banner bytes</span>
                        <strong>{scan.input?.bannerBytes ?? "n/a"}</strong>
                      </div>
                      <div>
                        <span>Banner timeout</span>
                        <strong>{scan.input?.bannerTimeout ?? "n/a"}s</strong>
                      </div>
                      <div>
                        <span>Banner send</span>
                        <strong>{scan.input?.bannerSend || "n/a"}</strong>
                      </div>
                      <div>
                        <span>Live check</span>
                        <strong>{scan.input?.noLiveCheck ? "off" : "on"}</strong>
                      </div>
                      <div>
                        <span>Shodan</span>
                        <strong>{scan.input?.shodanEnabled === false ? "off" : "on"}</strong>
                      </div>
                    </div>
                  </div>
                  <span className={`status-pill ${scan.status || "queued"}`}>{scan.status || "queued"}</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="muted">No scans are running or queued.</div>
          )}
        </div>
        {error ? <div className="error">{error}</div> : null}
        <button className="ghost" onClick={loadQueue} disabled={loading}>
          {loading ? "Refreshing..." : "Refresh Queue"}
        </button>
      </section>
    </div>
  );
}
