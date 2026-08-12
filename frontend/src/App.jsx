import { useState } from "react";
import { Route, HashRouter as Router, Routes } from "react-router-dom";
import { Header } from "@/components/layout/Header";
import { Sidebar } from "@/components/layout/Sidebar";
import Activity from "@/pages/Activity";
import Alerts from "@/pages/Alerts";
import Dashboard from "@/pages/Dashboard";
import Investigate from "@/pages/Investigate";
import Settings from "@/pages/Settings";

export default function App() {
  const [sidebarOpen, setSidebarOpen] = useState(false);

  return (
    <Router>
      <div className="flex min-h-screen bg-background">
        <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />
        <div className="flex min-w-0 flex-1 flex-col">
          <Header onMenuClick={() => setSidebarOpen(true)} />
          <main className="min-w-0 flex-1 overflow-y-auto p-6">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/investigate" element={<Investigate />} />
              <Route path="/alerts" element={<Alerts />} />
              <Route path="/activity" element={<Activity />} />
              <Route path="/settings" element={<Settings />} />
            </Routes>
          </main>
        </div>
      </div>
    </Router>
  );
}
