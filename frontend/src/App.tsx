import React, { useEffect } from 'react';
import { useVigilStore } from './store';
import { vigilClient } from './api';
import { Agent, Incident, AuditEntry, WSEventType } from './types';

// Import New Redesigned Modular Components
import { CommandBar } from './components/CommandBar';
import { AgentSidebar } from './components/AgentSidebar';
import { AgentProfile } from './components/AgentProfile';
import { SimulationDock } from './components/SimulationDock';
import { OperationsView } from './components/OperationsView';
import { ReplayView } from './components/ReplayView';
import { GovernanceView } from './components/GovernanceView';
import { ExecutiveView } from './components/ExecutiveView';
import { ThreatIntelligenceDashboard } from './components/ThreatIntelligenceDashboard';

const App: React.FC = () => {
  const {
    activeTab,
    setAgents,
    updateAgent,
    addIncident,
    updateIncidentExplanation,
    addAuditEntry,
    setAuditLog,
    setConnected,
    setTelegramStatus,
    setPendingApprovals,
    setTelegramUsers,
  } = useVigilStore();

  useEffect(() => {
    // 1. Establish WebSocket Connection
    vigilClient.connect();
    
    // 2. Wire Connection Status Updates
    vigilClient.onConnectionChange = (status) => {
      setConnected(status);
    };

    // 3. Register Global WebSocket Pipeline Interceptors
    const cleanupEventBus = vigilClient.onEvent((event) => {
      console.log(`[VIGIL App] Received pipeline WS event: ${event.type}`, event.payload);
      
      switch (event.type) {
        case WSEventType.AGENT_UPDATE:
          updateAgent(event.payload as Agent);
          break;
        case WSEventType.INCIDENT_DETECTED:
          addIncident(event.payload as Incident);
          // Refetch approvals in case it was a new approval card request
          vigilClient.getTelegramApprovals().then(setPendingApprovals).catch(console.error);
          break;
        case WSEventType.EXPLANATION_READY:
          updateIncidentExplanation(
            event.payload.incident_id as string, 
            event.payload.explanation as string
          );
          break;
        case WSEventType.AUDIT_LOG_ENTRY:
          addAuditEntry(event.payload as AuditEntry);
          break;
        case WSEventType.TELEGRAM_STATUS:
          setTelegramStatus(event.payload as any);
          // Refetch approvals on status change
          vigilClient.getTelegramApprovals().then(setPendingApprovals).catch(console.error);
          break;
        case 'INIT' as any:
          if (event.payload.telegramStatus) setTelegramStatus(event.payload.telegramStatus);
          if (event.payload.pendingApprovals) setPendingApprovals(event.payload.pendingApprovals);
          if (event.payload.telegramUsers) setTelegramUsers(event.payload.telegramUsers);
          break;
        default:
          break;
      }
    });

    // 4. Initial Fetch Bootstrap loader
    const loadInitialState = async () => {
      try {
        const loadedAgents = await vigilClient.getAgents();
        setAgents(loadedAgents);
        
        const loadedAudit = await vigilClient.getAuditLog();
        setAuditLog(loadedAudit);
        
        const loadedIncidents = await vigilClient.getIncidents();
        loadedIncidents.forEach((inc) => addIncident(inc));

        // Load initial Telegram stats
        try {
          const loadedTelStatus = await vigilClient.getTelegramStatus();
          setTelegramStatus(loadedTelStatus);
          const loadedApprovals = await vigilClient.getTelegramApprovals();
          setPendingApprovals(loadedApprovals);
          const loadedUsers = await vigilClient.getTelegramUsers();
          setTelegramUsers(loadedUsers);
        } catch (telErr) {
          console.warn("Telegram bot endpoint unavailable:", telErr);
        }
      } catch (err) {
        console.error("Failed to load initial REST bootstrap state:", err);
      }
    };

    loadInitialState();

    // 5. Cleanup on Unmount
    return () => {
      cleanupEventBus();
      vigilClient.disconnect();
    };
  }, [setAgents, updateAgent, addIncident, updateIncidentExplanation, addAuditEntry, setAuditLog, setConnected, setTelegramStatus, setPendingApprovals, setTelegramUsers]);

  // Dynamically render viewport matching selected navigation tab
  const renderMainView = () => {
    switch (activeTab) {
      case 'operations':
        return <OperationsView />;
      case 'replay':
        return <ReplayView />;
      case 'governance':
        return <GovernanceView />;
      case 'executive':
        return <ExecutiveView />;
      case 'threat_intel':
        return <ThreatIntelligenceDashboard />;
      default:
        return <OperationsView />;
    }
  };

  return (
    <div className="w-screen h-screen flex flex-col bg-vigil-bg text-vigil-text overflow-hidden font-sans select-none relative">
      
      {/* 1. Global Navigation Top Bar Component */}
      <CommandBar />

      {/* 2. Main Executive Operational Body Container */}
      <div className="flex-grow flex h-[calc(100vh-120px)] overflow-hidden relative">
        
        {/* Left Sidebar Agent Intelligence */}
        <AgentSidebar />

        {/* Dynamic Center Main Viewport */}
        <main className="flex-1 flex flex-col h-full overflow-hidden min-w-0 bg-slate-950/20 relative">
          {renderMainView()}
        </main>

        {/* Slide-out Agent Profile Details overlay Panel */}
        <AgentProfile />
      </div>

      {/* 3. Bottom Simulator Cyber Warfare Dock Component */}
      <SimulationDock />

    </div>
  );
};

export default App;
