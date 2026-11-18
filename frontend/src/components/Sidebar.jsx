import React from 'react';
import {
  LayoutDashboard,
  UploadCloud,
  Activity,
  ShieldAlert,
  FileSearch,
  Bot,
  Cpu,
  FileText,
  ShieldCheck,
  AlertTriangle
} from 'lucide-react';

export default function Sidebar({ activePage, setActivePage, backendStatus, activeAnalysisId }) {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard Overview', icon: LayoutDashboard },
    { id: 'upload', label: 'Dataset Upload', icon: UploadCloud },
    { id: 'progress', label: 'Analysis Progress', icon: Activity, badge: activeAnalysisId ? 'Active' : null },
    { id: 'threats', label: 'Threat Detection', icon: ShieldAlert },
    { id: 'investigation', label: 'Investigation Details', icon: FileSearch },
    { id: 'agents', label: 'Agent Monitoring', icon: Bot },
    { id: 'models', label: 'Model Performance', icon: Cpu },
    { id: 'reports', label: 'Security Reports', icon: FileText },
  ];

  return (
    <aside className="w-64 bg-[#14213d] border-r border-[#f4eded]/15 flex flex-col min-h-screen text-[#f4eded]">
      {/* Brand Header */}
      <div className="p-5 border-b border-[#f4eded]/15 flex items-center gap-3">
        <div className="w-9 h-9 rounded-lg bg-[#ff6b5b] flex items-center justify-center text-[#14213d] font-black text-xl shadow-lg">
          CS
        </div>
        <div>
          <h1 className="font-bold tracking-wider text-base uppercase text-[#f4eded]">CyberSentinel</h1>
          <p className="text-[11px] text-[#f4eded]/60 tracking-tight">Autonomous Multi-Agent SOC</p>
        </div>
      </div>

      {/* Navigation Links */}
      <nav className="flex-1 p-3 space-y-1.5 overflow-y-auto">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activePage === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActivePage(item.id)}
              className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-lg text-xs font-medium transition-all ${
                isActive
                  ? 'bg-[#ff6b5b] text-[#14213d] font-bold shadow-md shadow-[#ff6b5b]/20'
                  : 'text-[#f4eded]/80 hover:bg-[#f4eded]/10 hover:text-[#f4eded]'
              }`}
            >
              <div className="flex items-center gap-3">
                <Icon className={`w-4 h-4 ${isActive ? 'text-[#14213d]' : 'text-[#ff6b5b]'}`} />
                <span>{item.label}</span>
              </div>
              {item.badge && (
                <span className={`text-[10px] px-1.5 py-0.5 rounded uppercase tracking-wider font-bold ${
                  isActive ? 'bg-[#14213d] text-[#ff6b5b]' : 'bg-[#ff6b5b] text-[#14213d]'
                }`}>
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* System Health Footer */}
      <div className="p-4 border-t border-[#f4eded]/15 bg-[#14213d]/60">
        <div className="flex items-center justify-between text-xs mb-2">
          <span className="text-[#f4eded]/70">FastAPI Gateway</span>
          <div className="flex items-center gap-1.5">
            <span className={`w-2 h-2 rounded-full ${backendStatus === 'healthy' ? 'bg-[#f4eded] animate-ping' : 'bg-[#ff6b5b]'}`}></span>
            <span className="font-mono text-[11px] uppercase tracking-wider">
              {backendStatus === 'healthy' ? 'ONLINE' : 'STANDBY'}
            </span>
          </div>
        </div>
        <div className="text-[11px] text-[#f4eded]/50 font-mono">
          Host: 127.0.0.1:8000
        </div>
      </div>
    </aside>
  );
}
