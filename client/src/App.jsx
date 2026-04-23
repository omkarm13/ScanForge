import React from "react";
import { BrowserRouter, NavLink, Route, Routes } from "react-router-dom";
import HistoryPage from "./pages/HistoryPage.jsx";
import QueuePage from "./pages/QueuePage.jsx";
import ScanPage from "./pages/ScanPage.jsx";

function AppLayout() {
  const navClass = ({ isActive }) => (isActive ? "active" : undefined);

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand-block">
          <div className="brand">ScanForge</div>
          <span className="brand-tag">Port intelligence console</span>
        </div>
        <nav className="nav">
          <NavLink to="/" end className={navClass}>
            Scan
          </NavLink>
          <NavLink to="/queue" className={navClass}>
            Queue
          </NavLink>
          <NavLink to="/history" className={navClass}>
            History
          </NavLink>
        </nav>
        <div className="topbar-actions">
          <span className="status-indicator">
            <span className="status-dot" />
            Live
          </span>
        </div>
      </header>
      <main className="page">
        <Routes>
          <Route path="/" element={<ScanPage />} />
          <Route path="/queue" element={<QueuePage />} />
          <Route path="/history" element={<HistoryPage />} />
        </Routes>
      </main>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AppLayout />
    </BrowserRouter>
  );
}
