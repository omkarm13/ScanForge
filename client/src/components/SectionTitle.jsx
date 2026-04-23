import React from "react";

export default function SectionTitle({ kicker, title, desc }) {
  return (
    <div className="section-title">
      <div className="kicker">{kicker}</div>
      <h2>{title}</h2>
      <p>{desc}</p>
    </div>
  );
}
