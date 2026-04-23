import React from "react";

export default function TargetPills({ targets }) {
  return (
    <div className="pill-row">
      {targets.map((target) => (
        <span className="pill" key={target}>
          {target}
        </span>
      ))}
    </div>
  );
}
