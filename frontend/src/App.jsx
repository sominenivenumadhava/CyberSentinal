import React, { useState, useEffect } from 'react';
import axios from 'axios';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import DashboardOverview from './pages/DashboardOverview';
import DatasetUpload from './pages/DatasetUpload';
import AnalysisProgress from './pages/AnalysisProgress';
import ThreatDetection from './pages/ThreatDetection';
import InvestigationDetails from './pages/InvestigationDetails';
import AgentMonitoring from './pages/AgentMonitoring';
import ModelPerformance from './pages/ModelPerformance';
import SecurityReports from './pages/SecurityReports';

export default function App() {
  const [activePage, setActivePage] = useState('dashboard');
  const [backendStatus, setBackendStatus] = useState('connecting');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [activeAnalysisId, setActiveAnalysisId] = useState(null);
  const [analysisData, setAnalysisData] = useState(null);
  const [agentsStatus, setAgentsStatus] = useState(null);
  const [modelMetrics, setModelMetrics] = useState(null);
  const [pastAnalyses, setPastAnalyses] = useState([]);

  // Fetch initial telemetry and health
  useEffect(() => {
    // 1. Health check
    axios.get('/health')
      .then(res => setBackendStatus(res.data.status))
      .catch(() => setBackendStatus('offline'));

    // 2. Agents status
    axios.get('/api/agents/status')
      .then(res => setAgentsStatus(res.data))
      .catch(err => console.error("Error fetching agent status:", err));

    // 3. Model metrics
    axios.get('/api/models/metrics')
      .then(res => setModelMetrics(res.data))
      .catch(err => console.error("Error fetching model metrics:", err));

    // 4. Past analyses
    axios.get('/api/analyses')
      .then(res => {
        setPastAnalyses(res.data);
        if (res.data && res.data.length > 0) {
          const latest = res.data[0];
          setActiveAnalysisId(latest.analysis_id);
          // Fetch full result for latest
          axios.get(`/api/results/${latest.analysis_id}`)
            .then(rRes => setAnalysisData(rRes.data))
            .catch(() => {});
        }
      })
      .catch(() => {});
  }, []);

  // Trigger Autonomous Multi-Agent Investigation
  const handleTriggerAnalysis = async ({ file_id = 'dev_sample', sample_size = 50, raw_flows = null } = {}) => {
    setIsAnalyzing(true);
    setActivePage('progress');

    try {
      const response = await axios.post('/api/analyze', {
        file_id,
        sample_size,
        raw_flows,
      });

      const newAnalysisId = response.data.analysis_id;
      setActiveAnalysisId(newAnalysisId);

      // Fetch comprehensive result
      const resultsRes = await axios.get(`/api/results/${newAnalysisId}`);
      setAnalysisData(resultsRes.data);

      // Refresh past analyses list and agent stats
      axios.get('/api/analyses').then(r => setPastAnalyses(r.data)).catch(() => {});
      axios.get('/api/agents/status').then(r => setAgentsStatus(r.data)).catch(() => {});
    } catch (err) {
      console.error("Multi-Agent analysis error:", err);
      alert("Investigation error: " + (err.response?.data?.detail || err.message));
    } finally {
      setIsAnalyzing(false);
    }
  };

  const getPageTitle = () => {
    switch (activePage) {
      case 'dashboard': return 'SOC Threat Intelligence Dashboard';
      case 'upload': return 'Dataset Ingestion & Validation Gateway';
      case 'progress': return 'Autonomous Swarm Execution Tracker';
      case 'threats': return 'Telemetry Detection & Attribution Matrix';
      case 'investigation': return 'Correlated Campaign Investigations';
      case 'agents': return 'Multi-Agent Swarm Diagnostics & Audit';
      case 'models': return 'Empirical Deep Learning Benchmarks';
      case 'reports': return 'Executive Security Dossier & Mitigation';
      default: return 'CyberSentinel SOC';
    }
  };

  return (
    <div className="flex min-h-screen bg-[#14213d] text-[#f4eded]">
      {/* Sidebar Navigation */}
      <Sidebar
        activePage={activePage}
        setActivePage={setActivePage}
        backendStatus={backendStatus}
        activeAnalysisId={activeAnalysisId}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        <Header
          activePageTitle={getPageTitle()}
          onQuickAnalyze={() => handleTriggerAnalysis({ file_id: 'dev_sample', sample_size: 50 })}
          isAnalyzing={isAnalyzing}
          activeAnalysisId={activeAnalysisId}
        />

        <main className="flex-1 p-6 overflow-y-auto bg-[#14213d]">
          {activePage === 'dashboard' && (
            <DashboardOverview
              analysisData={analysisData}
              agentsStatus={agentsStatus}
              onNavigate={setActivePage}
              onQuickAnalyze={() => handleTriggerAnalysis({ file_id: 'dev_sample', sample_size: 50 })}
              isAnalyzing={isAnalyzing}
            />
          )}

          {activePage === 'upload' && (
            <DatasetUpload
              onAnalysisTriggered={handleTriggerAnalysis}
              isAnalyzing={isAnalyzing}
            />
          )}

          {activePage === 'progress' && (
            <AnalysisProgress
              activeAnalysisId={activeAnalysisId}
              analysisData={analysisData}
              isAnalyzing={isAnalyzing}
              onNavigate={setActivePage}
            />
          )}

          {activePage === 'threats' && (
            <ThreatDetection
              analysisData={analysisData}
            />
          )}

          {activePage === 'investigation' && (
            <InvestigationDetails
              analysisData={analysisData}
            />
          )}

          {activePage === 'agents' && (
            <AgentMonitoring
              agentsStatus={agentsStatus}
              analysisData={analysisData}
            />
          )}

          {activePage === 'models' && (
            <ModelPerformance
              modelMetrics={modelMetrics}
            />
          )}

          {activePage === 'reports' && (
            <SecurityReports
              analysisData={analysisData}
              activeAnalysisId={activeAnalysisId}
              pastAnalyses={pastAnalyses}
              onSelectAnalysis={(id) => {
                setActiveAnalysisId(id);
                axios.get(`/api/results/${id}`).then(r => setAnalysisData(r.data)).catch(() => {});
              }}
            />
          )}
        </main>
      </div>
    </div>
  );
}
