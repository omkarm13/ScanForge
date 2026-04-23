import React, { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import ScanResults from "../components/ScanResults.jsx";
import SectionTitle from "../components/SectionTitle.jsx";
import TargetPills from "../components/TargetPills.jsx";
import { fetchHistory, fetchScan, runScan } from "../api/scans.js";

const defaultPorts = "1-100,8181";

export default function ScanPage() {
  const [ports, setPorts] = useState(defaultPorts);
  const [targets, setTargets] = useState(
    "91.242.69.142\ncanvas-demo.internetscout.org\n162.212.173.114"
  );
  const [useLiveCheck, setUseLiveCheck] = useState(true);
  const [bannerBytes, setBannerBytes] = useState(1024);
  const [bannerTimeout, setBannerTimeout] = useState(1.0);
  const [bannerSend, setBannerSend] = useState("");
  const [udpPorts, setUdpPorts] = useState("53");
  const [enableUdp, setEnableUdp] = useState(true);
  const [dnsVersionProbe, setDnsVersionProbe] = useState(true);
  const [shodanEnabled, setShodanEnabled] = useState(true);
  const [activeScan, setActiveScan] = useState(null);
  const [pollId, setPollId] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const parsedTargets = useMemo(
    () =>
      targets
        .split(/\r?\n/)
        .map((target) => target.trim())
        .filter(Boolean),
    [targets]
  );

  const onRun = async () => {
    setLoading(true);
    setError("");
    try {
      const payload = {
        ports,
        targets: parsedTargets,
        noLiveCheck: !useLiveCheck,
        bannerBytes,
        bannerTimeout,
        bannerSend,
        enableUdp,
        udpPorts,
        dnsVersionProbe,
        shodanEnabled,
      };
      const data = await runScan(payload);
      setActiveScan(data);
      if (data?._id) {
        localStorage.setItem("scanforge:lastScanId", data._id);
      }
      if (data?._id) {
        setPollId(data._id);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!pollId) return;
    const timer = setInterval(async () => {
      try {
        const scan = await fetchScan(pollId);
        setActiveScan(scan);
        if (scan?._id) {
          localStorage.setItem("scanforge:lastScanId", scan._id);
        }
        if (scan.status === "completed" || scan.status === "failed") {
          setPollId(null);
        }
      } catch (err) {
        setError(err.message);
        setPollId(null);
      }
    }, 2000);
    return () => clearInterval(timer);
  }, [pollId]);

  useEffect(() => {
    const loadLatest = async () => {
      try {
        const lastId = localStorage.getItem("scanforge:lastScanId");
        if (lastId) {
          const scan = await fetchScan(lastId);
          setActiveScan(scan);
          if (scan.status === "running" || scan.status === "queued") {
            setPollId(lastId);
          }
          return;
        }
        const history = await fetchHistory();
        if (history.length) {
          setActiveScan(history[0]);
        }
      } catch (err) {
        setError(err.message);
      }
    };

    loadLatest();
  }, []);

  const isRunning = loading || Boolean(pollId);

  return (
    <div className="page-content">
      <header className="hero">
        <div className="hero-card">
          <div className="brand">ScanForge</div>
          <h1>Precision port intelligence with visual clarity.</h1>
          <p>
            Run deep port scans, capture banners, and enrich with Shodan CVEs - all from a single, persistent control room.
          </p>
          <div className="hero-actions">
            <button className="primary" onClick={onRun} disabled={isRunning}>
              {isRunning ? "Running..." : "Run Scan"}
            </button>
            <Link className="ghost link-button" to="/history">
              View History
            </Link>
          </div>
        </div>
        <div className="hero-panel">
          <div className="panel-title">Targets Preview</div>
          <TargetPills targets={parsedTargets} />
          <div className="panel-stats">
            <div>
              <span>Targets</span>
              <strong>{parsedTargets.length}</strong>
            </div>
            <div>
              <span>Ports</span>
              <strong>{ports}</strong>
            </div>
          </div>
        </div>
      </header>

      <section className="scan-layout">
        <div className="card scan-inputs">
          <SectionTitle kicker="Targets" title="Scan Inputs" desc="Paste IPs, domains, or CIDRs. One per line." />
          <div className="targets-meta">
            <span>Targets detected</span>
            <strong>{parsedTargets.length}</strong>
          </div>
          <textarea
            value={targets}
            onChange={(event) => setTargets(event.target.value)}
            rows={10}
            placeholder="example.com\n1.1.1.1\n8.8.8.0/24"
          />
          <p className="input-help">Tip: You can mix IPs, domains, and CIDR ranges in the same list.</p>
        </div>

        <div className="scan-settings">
          <div className="card">
            <SectionTitle kicker="Config" title="Scan Settings" desc="Tune the ports and banner capture parameters." />
            <div className="field-row">
              <label>
                Ports
                <input value={ports} onChange={(event) => setPorts(event.target.value)} />
              </label>
              <label>
                Banner bytes
                <input
                  type="number"
                  value={bannerBytes}
                  onChange={(event) => setBannerBytes(Number(event.target.value))}
                />
              </label>
            </div>
            <div className="field-row">
              <label>
                Banner timeout (s)
                <input
                  type="number"
                  step="0.1"
                  value={bannerTimeout}
                  onChange={(event) => setBannerTimeout(Number(event.target.value))}
                />
              </label>
              <label>
                Banner send
                <input value={bannerSend} onChange={(event) => setBannerSend(event.target.value)} />
              </label>
            </div>
            <div className="field-row">
              <label>
                UDP ports
                <input value={udpPorts} onChange={(event) => setUdpPorts(event.target.value)} />
              </label>
              <label className="toggle">
                <input
                  type="checkbox"
                  checked={enableUdp}
                  onChange={(event) => setEnableUdp(event.target.checked)}
                />
                <span>Enable UDP probes</span>
              </label>
            </div>
            <label className="toggle">
              <input
                type="checkbox"
                checked={dnsVersionProbe}
                onChange={(event) => setDnsVersionProbe(event.target.checked)}
              />
              <span>DNS version probe (TCP/UDP 53)</span>
            </label>
          </div>
          <div className="card">
            <SectionTitle kicker="Checks" title="Enrichment" desc="Enable live discovery and Shodan context." />
            <div className="toggles">
              <label className="toggle">
                <input
                  type="checkbox"
                  checked={useLiveCheck}
                  onChange={(event) => setUseLiveCheck(event.target.checked)}
                />
                <span>Live check (ping + TCP fallback)</span>
              </label>
              <label className="toggle">
                <input
                  type="checkbox"
                  checked={shodanEnabled}
                  onChange={(event) => setShodanEnabled(event.target.checked)}
                />
                <span>Shodan CVE enrichment</span>
              </label>
            </div>
            {error ? <div className="error">{error}</div> : null}
          </div>
        </div>
      </section>

      <section className="results-layout">
        <div className="card">
          <SectionTitle kicker="Results" title="Latest Scan" desc="Most recent scan details and banners." />
          <ScanResults scan={activeScan} loading={loading || Boolean(pollId)} />
        </div>
      </section>
    </div>
  );
}
