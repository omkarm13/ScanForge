import React from "react";

export default function BannerBlock({ banners }) {
  const entries = Object.entries(banners || {});
  if (!entries.length) return <span className="muted">No banners</span>;
  return (
    <div className="banner-list">
      {entries.map(([port, text]) => (
        <div className="banner-item" key={port}>
          <div className="banner-port">Port {port}</div>
          <pre>{text}</pre>
        </div>
      ))}
    </div>
  );
}
