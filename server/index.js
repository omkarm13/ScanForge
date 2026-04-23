import cors from "cors";
import dotenv from "dotenv";
import express from "express";
import mongoose from "mongoose";
import path from "path";
import { fileURLToPath } from "url";
import { resolveTargets, scanTargets } from "./scanner.js";
import Scan from "./models/Scan.js";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));

const mongoUri = process.env.MONGO_URI;
const port = process.env.PORT || 5050;
const queue = [];
let workerBusy = false;

mongoose
  .connect(mongoUri)
  .then(() => console.log("Mongo connected"))
  .catch((err) => {
    console.error("Mongo connection error", err);
    process.exit(1);
  });

app.get("/api/health", (req, res) => {
  res.json({ ok: true });
});

app.get("/api/scans", async (req, res) => {
  const scans = await Scan.find().sort({ createdAt: -1 }).limit(100).lean();
  res.json(scans);
});

app.get("/api/scans/:id", async (req, res) => {
  const scan = await Scan.findById(req.params.id).lean();
  if (!scan) {
    return res.status(404).json({ error: "Not found" });
  }
  res.json(scan);
});

app.get("/api/queue", async (req, res) => {
  const completed = await Scan.countDocuments({ status: "completed" });
  const failed = await Scan.countDocuments({ status: "failed" });
  res.json({
    waiting: queue.length,
    active: workerBusy ? 1 : 0,
    completed,
    failed,
  });
});

app.post("/api/scan", async (req, res) => {
  try {
    const config = req.body || {};
    const resolved = await resolveTargets(config);
    if (resolved.targets.length === 0) {
      return res.status(400).json({ error: "No targets resolved" });
    }
    const doc = await Scan.create({
      input: config,
      resolvedTargets: resolved.targets,
      status: "queued",
    });

    queue.push({
      scanId: doc._id.toString(),
      config,
      resolvedTargets: resolved.targets,
      baseTargets: resolved.baseTargets,
    });

    res.json({
      _id: doc._id,
      status: "queued",
    });
  } catch (err) {
    res.status(500).json({ error: err.message || "Scan failed" });
  }
});

const runWorker = async () => {
  if (workerBusy || queue.length === 0) return;
  workerBusy = true;
  const job = queue.shift();
  try {
    const { scanId, config, resolvedTargets, baseTargets } = job;
    await Scan.updateOne({ _id: scanId }, { status: "running" });
    const result = await scanTargets({
      ...config,
      targets: resolvedTargets,
      shodanTargets: baseTargets,
    });
    await Scan.updateOne(
      { _id: scanId },
      {
        scanResult: result.scanResult,
        banners: result.banners,
        shodanResult: result.shodanResult,
        stats: result.stats,
        status: "completed",
      }
    );
  } catch (err) {
    await Scan.updateOne(
      { _id: job.scanId },
      {
        status: "failed",
        stats: { error: err.message },
      }
    );
  } finally {
    workerBusy = false;
    if (queue.length > 0) setImmediate(runWorker);
  }
};

setInterval(runWorker, 1000);

app.get("/api/scans/:id/export", async (req, res) => {
  const scan = await Scan.findById(req.params.id).lean();
  if (!scan) return res.status(404).json({ error: "Not found" });
  const format = (req.query.format || "json").toLowerCase();
  if (format === "csv") {
    const rows = [];
    rows.push(["target", "port", "banner"].join(","));
    for (const [host, ports] of Object.entries(scan.scanResult || {})) {
      const bannerMap = scan.banners?.[host] || {};
      if (!ports.length) rows.push([host, "", ""].join(","));
      for (const port of ports) {
        const banner = String(bannerMap[port] || "").replace(/\r?\n/g, " ").replace(/"/g, '""');
        rows.push(`${host},${port},"${banner}"`);
      }
    }
    res.setHeader("Content-Type", "text/csv");
    res.setHeader("Content-Disposition", `attachment; filename="scan-${scan._id}.csv"`);
    return res.send(rows.join("\n"));
  }
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Content-Disposition", `attachment; filename="scan-${scan._id}.json"`);
  return res.json(scan);
});

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const clientBuild = path.join(__dirname, "../client/dist");

app.use(express.static(clientBuild));

app.get("*", (req, res) => {
  res.sendFile(path.join(clientBuild, "index.html"));
});

app.listen(port, () => {
  console.log(`Server running on ${port}`);
});
