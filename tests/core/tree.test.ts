import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { HierarchicalTree } from '../../src/lib/tree';
import { MockAgentConnector } from '../../src/lib/agents/mock';

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(path.join(tmpdir(), 'hightower-tree-'));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('HierarchicalTree', () => {
  it('discovers hierarchy once, builds recursively, persists, reloads, and queries leaves', async () => {
    const connector = new MockAgentConnector();
    const tree = new HierarchicalTree({
      problemStatement: 'Decompose this generic document.',
      fullData: '# Doc\n## A\nAlpha says red.\n## B\nBeta says blue.',
      apiConfig: { baseUrl: 'mock://local', apiKey: 'mock', model: 'mock' },
      dataDir: dir,
      connector
    });

    const built = await tree.build();
    expect(built.hierarchy.levels.map((l) => l.name)).toEqual(['document', 'section']);
    expect(built.nodes.filter((n) => n.parentId === built.rootNodeId)).toHaveLength(2);
    expect(built.validation.valid).toBe(true);

    const loaded = await HierarchicalTree.load(built.id, { dataDir: dir, connector });
    expect(loaded.snapshot().nodes).toHaveLength(3);

    const answer = await loaded.query('What colors are mentioned?');
    expect(answer.answer).toContain('red');
    expect(answer.answer).toContain('blue');
    expect(answer.reasoning).toContain('root');
  });
});
