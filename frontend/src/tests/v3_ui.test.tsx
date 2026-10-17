import { describe, it, expect } from 'vitest';
import { renderToString } from 'react-dom/server';
import fs from 'node:fs';
import path from 'node:path';

import { ContainmentPill, TIER_CONFIGS, ContainmentTierType } from '../components/ContainmentPill';
import { AntibodyCard, AntibodyBacktestData } from '../components/AntibodyCard';
import { TaintGraph } from '../components/TaintGraph';
import { BlastRadiusView, BlastRadiusDAG } from '../components/BlastRadiusView';
import { ArchitectureExplorer } from '../components/ArchitectureExplorer';

describe('VIGIL v3 UI Components', () => {
  // 1. ContainmentPill Tests (4 graduated tiers)
  describe('ContainmentPill', () => {
    it('renders all four containment tiers with appropriate styling and labels', () => {
      const tiers: ContainmentTierType[] = ['LOG_ONLY', 'DOWNGRADE_SCOPE', 'SHADOW_SANDBOX', 'QUARANTINE_ROLLBACK'];

      for (const tier of tiers) {
        const html = renderToString(
          <ContainmentPill tier={tier} ledgerEntryId="entry-test-12345678" />
        );
        expect(html).toContain(TIER_CONFIGS[tier].label);
        expect(html).toContain(`data-tier="${tier}"`);
        expect(html).toContain('#entry-te');
      }
    });

    it('renders without ledger ID gracefully', () => {
      const html = renderToString(<ContainmentPill tier="LOG_ONLY" />);
      expect(html).toContain('NORMAL');
      expect(html).not.toContain('pill-ledger-link');
    });
  });

  // 2. AntibodyCard Tests
  describe('AntibodyCard', () => {
    const fixtureReady: AntibodyBacktestData = {
      candidate: {
        pattern: { tool: 'billing_database', argument_shape_class: 'wildcard' },
        armoriq_constraint: 'deny',
        rationale: 'Block billing DB queries on tainted delegations',
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

    it('displays computed false-block bound and recall from props with no hard-coding', () => {
      const html = renderToString(<AntibodyCard data={fixtureReady} />);
      expect(html).toContain('0 of 500; upper bound 0.6%');
      expect(html).toContain('100.0%');
      expect(html).toContain('READY FOR REVIEW');
      expect(html).toContain('Submit for approval');
    });

    it('disables submit button and shows rejection reason when false block occurs', () => {
      const fixtureRejected: AntibodyBacktestData = {
        ...fixtureReady,
        observed_false_blocks: 1,
        is_ready_for_review: false,
        rejection_reason: 'Rejected: candidate caused 1 false blocks on benign traffic',
      };
      const html = renderToString(<AntibodyCard data={fixtureRejected} />);
      expect(html).toContain('REJECTED IN BACKTEST');
      expect(html).toContain('caused 1 false blocks');
      expect(html).toContain('disabled=""');
    });
  });

  // 3. TaintGraph Tests
  describe('TaintGraph', () => {
    it('renders nodes and delegation edges with reduced-motion support', () => {
      const html = renderToString(<TaintGraph reducedMotion={true} />);
      expect(html).toContain('CustomerBot');
      expect(html).toContain('AnalyticsAgent');
      expect(html).toContain('BillingAgent');
      expect(html).toContain('EXTERNAL_UNTRUSTED');
      expect(html).toContain('TicketSummary');
    });
  });

  // 4. BlastRadiusView Tests
  describe('BlastRadiusView', () => {
    it('renders DAG operations with REVERSED and IRREVERSIBLE status', () => {
      const mockDag: BlastRadiusDAG = {
        trace_id: 'trace-v7-test',
        total_nodes: 2,
        nodes: [
          {
            id: 'span-rev-1',
            tool: 'update_customer_account',
            agent_id: 'customer-bot',
            is_state_changing: true,
            status: 'REVERSED',
            pre_hash: 'hash123',
            timestamp: 1000,
          },
          {
            id: 'span-irrev-2',
            tool: 'send_external_email',
            agent_id: 'customer-bot',
            is_state_changing: true,
            status: 'IRREVERSIBLE',
            reason: 'Email dispatched across SMTP',
            timestamp: 1001,
          },
        ],
        edges: [{ from: 'span-rev-1', to: 'span-irrev-2' }],
      };

      const html = renderToString(<BlastRadiusView dag={mockDag} />);
      expect(html).toContain('update_customer_account');
      expect(html).toContain('send_external_email');
      expect(html).toContain('REVERSED');
      expect(html).toContain('IRREVERSIBLE');
      expect(html).toContain('Email dispatched across SMTP');
    });
  });

  // 5. ArchitectureExplorer Tests
  describe('ArchitectureExplorer', () => {
    it('renders all phases linking to verifiable evidence paths', () => {
      const html = renderToString(<ArchitectureExplorer />);
      expect(html).toContain('Phase V0');
      expect(html).toContain('Phase V1');
      expect(html).toContain('Phase V6');
      expect(html).toContain('evidence/V1/live_taint_enforcement.json');
      expect(html).toContain('evidence/V6/rollback_receipt.json');
    });
  });

  // 6. Rule D Static Metric Scanner: No hard-coded metrics in src/
  describe('Rule D Compliance: No hardcoded metric literals in src/', () => {
    it('verifies that components compute metrics from API/props rather than hardcoding', () => {
      const srcDir = path.resolve(process.cwd(), 'src');
      
      const getAllFiles = (dir: string, ext = '.tsx'): string[] => {
        let results: string[] = [];
        if (!fs.existsSync(dir)) return results;
        const list = fs.readdirSync(dir);
        for (const file of list) {
          const filePath = path.join(dir, file);
          const stat = fs.statSync(filePath);
          if (stat && stat.isDirectory()) {
            if (!file.includes('tests') && !file.includes('node_modules')) {
              results = results.concat(getAllFiles(filePath, ext));
            }
          } else if (file.endsWith(ext)) {
            results.push(filePath);
          }
        }
        return results;
      };

      const files = getAllFiles(srcDir);
      expect(files.length).toBeGreaterThan(0);

      for (const filePath of files) {
        const content = fs.readFileSync(filePath, 'utf-8');
        expect(content).not.toMatch(/['"]0(?:\.0+)?%\s+false\s+positives?['"]/i);
        expect(content).not.toMatch(/['"]0(?:\.0+)?%\s+FPR['"]/i);
        expect(content).not.toMatch(/['"]22%['"]/);
        expect(content).not.toMatch(/['"]3\s+seconds?['"]/i);
      }
    });
  });
});
