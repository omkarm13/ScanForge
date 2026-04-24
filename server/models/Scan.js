import mongoose from "mongoose";

const ScanSchema = new mongoose.Schema(
  {
    input: { type: Object, required: true },
    resolvedTargets: { type: [String], default: [] },
    scanResult: { type: Object, default: {} },
    banners: { type: Object, default: {} },
    shodanResult: { type: Object, default: {} },
    corsResult: { type: Object, default: {} },
    stats: { type: Object, default: {} },
    status: { type: String, default: "queued" },
    jobId: { type: String },
  },
  { timestamps: true }
);

export default mongoose.model("Scan", ScanSchema);
