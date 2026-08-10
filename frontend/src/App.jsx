import { Route, HashRouter as Router, Routes } from "react-router-dom";
import { Sidebar } from "@/components/layout/Sidebar";
import Dashboard from "@/pages/Dashboard";

function Placeholder({ title }) {
  return (
    <div>
      <h1 className="text-xl font-bold text-foreground">{title}</h1>
      <p className="mt-2 text-sm text-muted-foreground">Bu modül henüz geliştirilme aşamasında.</p>
    </div>
  );
}

export default function App() {
  return (
    <Router>
      <div className="flex min-h-screen bg-background">
        <Sidebar />
        <main className="flex-1 overflow-y-auto p-6">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/investigate" element={<Placeholder title="IOC İncele" />} />
            <Route path="/alerts" element={<Placeholder title="Uyarılar" />} />
            <Route path="/activity" element={<Placeholder title="Aktivite" />} />
            <Route path="/settings" element={<Placeholder title="Ayarlar" />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}
