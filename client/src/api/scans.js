const request = async (path, options) => {
  const res = await fetch(path, options);
  const text = await res.text();
  let data = {};

  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = { raw: text };
    }
  }

  if (!res.ok) {
    const message = data.error || data.raw || "Request failed";
    throw new Error(message);
  }

  return data;
};

export const fetchHistory = () => request("/api/scans");
export const fetchQueue = () => request("/api/queue");

export const runScan = (payload) =>
  request("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

export const fetchScan = (scanId) => request(`/api/scans/${scanId}`);
