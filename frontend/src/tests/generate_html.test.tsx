import { describe, it, expect } from 'vitest';
import { renderToString } from 'react-dom/server';
import fs from 'node:fs';
import path from 'node:path';

import { ContainmentPill, ContainmentTierType } from '../components/ContainmentPill';
import { AntibodyCard, AntibodyBacktestData } from '../components/AntibodyCard';
import { TaintGraph } from '../components/TaintGraph';
import { BlastRadiusView, BlastRadiusDAG } from '../components/BlastRadiusView';

describe('Generate HTML previews for responsive screenshots', () => {
  it('generates HTML files for all 4 views', () => {
    const scratchDir = path.resolve(process.cwd(), '../scratch');
    fs.mkdirSync(scratchDir, { recursive: true });

    const distAssets = path.resolve(process.cwd(), 'dist/assets');
    let cssContent = '';
    if (fs.existsSync(distAssets)) {
      const cssFiles = fs.readdirSync(distAssets).filter(f => f.endsWith('.css'));
      if (cssFiles.length > 0) {
        cssContent = fs.readFileSync(path.join(distAssets, cssFiles[0]), 'utf-8');
      }
    }

    const wrapHtml = (title: string, bodyContent: string) => `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${title}</title>
  <style>
    ${cssContent}
    body { background-color: #030712; color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 24px; min-height: 100vh; display: flex; flex-direction: column; justify-content: center; align-items: center; }
  </style>
</head>
<body class="bg-vigil-bg text-vigil-text font-sans antialiased">
  <div style="width: 100%; max-width: 1100px; margin: 0 auto;">
    ${bodyContent}
  </div>
</body>
</html>`;

    // 1. Taint Graph
    const taintGraphHtml = wrapHtml('Taint Graph', renderToString(
      <div className="flex flex-col gap-4">
        <h2 className="text-xl font-bold font-mono tracking-wider text-cyan-400">VIGIL DIFC TAINT PROPAGATION GRAPH</h2>
        <TaintGraph reducedMotion={false} />
      </div>
    ));
    fs.writeFileSync(path.join(scratchDir, 'taint_graph.html'), taintGraphHtml, 'utf-8');

    // 2. Containment Pill (All 4 states)
    const tiers: ContainmentTierType[] = ['LOG_ONLY', 'DOWNGRADE_SCOPE', 'SHADOW_SANDBOX', 'QUARANTINE_ROLLBACK'];
    const pillsHtml = wrapHtml('Containment Pills', renderToString(
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-8 flex flex-col gap-6 shadow-2xl">
        <h2 className="text-xl font-bold font-mono tracking-wider text-emerald-400">VIGIL GRADUATED CONTAINMENT TIERS (FAST-MCP)</h2>
        <p className="text-sm text-slate-400">ArmorIQ-Authorized Real-Time Containment States</p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {tiers.map((t, idx) => (
            <div key={t} className="flex items-center justify-between p-4 bg-slate-950/60 border border-slate-800/80 rounded-xl">
              <span className="text-xs font-mono text-slate-400">Session sess-v3-00{idx+1}</span>
              <ContainmentPill tier={t} ledgerEntryId={`entry-tier-v3-00${idx+1}`} />
            </div>
          ))}
        </div>
      </div>
    ));
    fs.writeFileSync(path.join(scratchDir, 'containment_pill.html'), pillsHtml, 'utf-8');

    // 3. Antibody Card
    const fixtureReady: AntibodyBacktestData = {
      candidate: {
        pattern: { tool: 'billing_database', argument_shape_class: 'unbounded_customer_export' },
        armoriq_constraint: 'deny',
        rationale: 'Block unauthorized billing database export on tainted agent lineage',
      },
      benign_trials: 500,
      observed_false_blocks: 0,
      one_sided_95_upper_bound: 0.005974,
      attack_trials: 15,
      observed_attack_blocks: 15,
      recall: 1.0,
      is_ready_for_review: true,
      status_summary: '0 of 500; upper bound 0.6% (recall: 100.0%)',
    };
    const antibodyHtml = wrapHtml('Antibody Card', renderToString(
      <div className="max-w-xl mx-auto">
        <AntibodyCard data={fixtureReady} />
      </div>
    ));
    fs.writeFileSync(path.join(scratchDir, 'antibody_card.html'), antibodyHtml, 'utf-8');

    // 4. Blast Radius DAG
    const mockDag: BlastRadiusDAG = {
      trace_id: 'trace-v7-incident-8812',
      total_nodes: 4,
      nodes: [
        {
          id: 'span-01',
          tool: 'read_customer_ticket',
          agent_id: 'CustomerBot',
          is_state_changing: false,
          status: 'NOT_APPLICABLE',
          timestamp: 1729150000,
        },
        {
          id: 'span-02',
          tool: 'update_customer_record',
          agent_id: 'CustomerBot',
          is_state_changing: true,
          status: 'REVERSED',
          pre_hash: 'sha256-a1b2c3d4e5f6',
          timestamp: 1729150005,
        },
        {
          id: 'span-03',
          tool: 'write_analytics_cache',
          agent_id: 'AnalyticsAgent',
          is_state_changing: true,
          status: 'REVERSED',
          pre_hash: 'sha256-998877665544',
          timestamp: 1729150012,
        },
        {
          id: 'span-04',
          tool: 'send_external_email',
          agent_id: 'CustomerBot',
          is_state_changing: true,
          status: 'IRREVERSIBLE',
          reason: 'Out-of-band email dispatched across public SMTP boundary',
          timestamp: 1729150018,
        },
      ],
      edges: [
        { from: 'span-01', to: 'span-02' },
        { from: 'span-02', to: 'span-03' },
        { from: 'span-02', to: 'span-04' },
      ],
    };
    const blastRadiusHtml = wrapHtml('Blast Radius DAG', renderToString(
      <BlastRadiusView dag={mockDag} />
    ));
    fs.writeFileSync(path.join(scratchDir, 'blast_radius.html'), blastRadiusHtml, 'utf-8');

    expect(fs.existsSync(path.join(scratchDir, 'taint_graph.html'))).toBe(true);
    expect(fs.existsSync(path.join(scratchDir, 'containment_pill.html'))).toBe(true);
    expect(fs.existsSync(path.join(scratchDir, 'antibody_card.html'))).toBe(true);
    expect(fs.existsSync(path.join(scratchDir, 'blast_radius.html'))).toBe(true);
  });
});
