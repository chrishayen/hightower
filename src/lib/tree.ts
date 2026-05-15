import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { nanoid } from 'nanoid';
import { MockAgentConnector } from './agents/mock';
import { OpenAICompatibleConnector } from './agents/openaiCompatible';
import { discoveryPrompt, queryPrompt, splitPrompt } from './prompts';
import { parseJsonObject } from './json';
import { retry } from './retry';
import { mergeValidation, validateChildSlices } from './validation';
import type { AgentConnector, ApiConfig, ChildSliceSpec, HierarchySchema, NodeRecord, QueryResult, TreeEvent, TreeManifest, ValidationResult } from './types';

interface TreeOptions {
  problemStatement: string;
  fullData: string;
  apiConfig: ApiConfig;
  dataDir: string;
  connector?: AgentConnector;
  onEvent?: (event: TreeEvent) => void;
}

interface LoadOptions { dataDir: string; connector?: AgentConnector; onEvent?: (event: TreeEvent) => void }

export class HierarchicalTree {
  private manifest?: TreeManifest;
  private contexts = new Map<string, string>();
  private readonly id: string;
  private readonly connector: AgentConnector;
  private readonly dataDir: string;
  private readonly onEvent?: (event: TreeEvent) => void;

  constructor(private readonly options: TreeOptions) {
    this.id = nanoid();
    this.connector = options.connector ?? new OpenAICompatibleConnector(options.apiConfig);
    this.dataDir = options.dataDir;
    this.onEvent = options.onEvent;
  }

  static async load(id: string, options: LoadOptions): Promise<HierarchicalTree> {
    const manifestPath = path.join(options.dataDir, 'trees', id, 'manifest.json');
    const manifest = JSON.parse(await readFile(manifestPath, 'utf8')) as TreeManifest;
    const tree = new HierarchicalTree({
      problemStatement: manifest.problemStatement,
      fullData: await readFile(path.join(options.dataDir, 'trees', id, 'source.txt'), 'utf8'),
      apiConfig: { baseUrl: 'loaded://', apiKey: '', model: '' },
      dataDir: options.dataDir,
      connector: options.connector ?? new MockAgentConnector(),
      onEvent: options.onEvent
    });
    (tree as unknown as { manifest: TreeManifest; id: string }).manifest = manifest;
    for (const node of manifest.nodes) {
      tree.contexts.set(node.id, await readFile(path.join(options.dataDir, 'trees', id, node.contextPath), 'utf8'));
    }
    return tree;
  }

  async build(): Promise<TreeManifest> {
    this.emit({ type: 'job_started', treeId: this.id });
    const hierarchy = await this.discoverHierarchy();
    this.emit({ type: 'discovery_completed', hierarchy });
    const root: NodeRecord = {
      id: 'root', parentId: null, title: hierarchy.levels[0]?.name ?? 'root', role: hierarchy.rootRole,
      level: hierarchy.levels[0]?.name ?? 'root', levelIndex: 0, startOffset: 0, endOffset: this.options.fullData.length,
      contextPath: 'nodes/root.txt', childIds: []
    };
    this.contexts.set(root.id, this.options.fullData);
    const nodes: NodeRecord[] = [root];
    const validations: ValidationResult[] = [];
    await this.buildChildren(root, nodes, hierarchy, validations);
    const validation = mergeValidation(validations.length ? validations : [{ valid: true, errors: [], warnings: [] }]);
    const now = new Date().toISOString();
    this.manifest = { id: this.id, problemStatement: this.options.problemStatement, hierarchy, rootNodeId: root.id, nodes, validation, createdAt: now, updatedAt: now };
    await this.persist();
    this.emit({ type: 'job_completed', treeId: this.id });
    return this.manifest;
  }

  snapshot(): TreeManifest {
    if (!this.manifest) throw new Error('Tree has not been built or loaded');
    return this.manifest;
  }

  async query(question: string): Promise<QueryResult> {
    if (!this.manifest) throw new Error('Tree has not been built or loaded');
    const root = this.manifest.nodes.find((n) => n.id === this.manifest?.rootNodeId);
    if (!root) throw new Error('Root node missing');
    return this.queryNode(root, question);
  }

  private async discoverHierarchy(): Promise<HierarchySchema> {
    this.emit({ type: 'discovery_started', agentCount: 3 });
    const messages = (agent: number) => [
      { role: 'system' as const, content: discoveryPrompt(`discovery agent ${agent} for the entire provided input`) },
      { role: 'user' as const, content: `PROBLEM:\n${this.options.problemStatement}\n\nTEXT:\n${this.options.fullData}` }
    ];
    const outputs = await Promise.all([1, 2, 3].map((i) => retry(() => this.connector.complete(messages(i)), 3)));
    const schemas = outputs.map((o) => parseJsonObject<HierarchySchema>(o));
    return this.normalizeHierarchy(schemas[0]);
  }

  private normalizeHierarchy(schema: HierarchySchema): HierarchySchema {
    if (!schema.levels?.length) throw new Error('Discovery returned no hierarchy levels');
    return { rootRole: schema.rootRole || `the entire provided ${schema.levels[0].name}`, levels: schema.levels.map((l) => ({ name: l.name, roleTemplate: l.roleTemplate })) };
  }

  private async buildChildren(parent: NodeRecord, nodes: NodeRecord[], hierarchy: HierarchySchema, validations: ValidationResult[]): Promise<void> {
    this.emit({ type: 'node_started', nodeId: parent.id, title: parent.title, level: parent.level });
    const next = hierarchy.levels[parent.levelIndex + 1];
    if (!next) {
      this.emit({ type: 'node_completed', nodeId: parent.id, childCount: 0 });
      return;
    }
    const parentContext = this.contexts.get(parent.id) ?? '';
    const response = await retry(() => this.connector.complete([
      { role: 'system', content: splitPrompt(parent.role, parent.level, next.name) },
      { role: 'user', content: `TEXT:\n${parentContext}` }
    ]), 3);
    const parsed = parseJsonObject<{ children: ChildSliceSpec[] }>(response);
    if (!parsed.children.length) {
      this.emit({ type: 'node_completed', nodeId: parent.id, childCount: 0 });
      return;
    }
    const validation = validateChildSlices(parentContext, parsed.children);
    parent.validation = { valid: validation.valid, errors: validation.errors, warnings: validation.warnings };
    validations.push(parent.validation);
    if (!validation.valid) {
      this.emit({ type: 'validation_failed', nodeId: parent.id, errors: validation.errors });
      throw new Error(`Child validation failed for ${parent.id}: ${validation.errors.join('; ')}`);
    }
    for (let i = 0; i < validation.children.length; i += 1) {
      const childSpec = validation.children[i];
      const childId = `${parent.id}-${i + 1}`;
      const child: NodeRecord = {
        id: childId,
        parentId: parent.id,
        title: childSpec.title,
        role: childSpec.role ?? `${childSpec.title}, ${next.name} within ${parent.title}`,
        level: next.name,
        levelIndex: parent.levelIndex + 1,
        startOffset: childSpec.startOffset,
        endOffset: childSpec.endOffset,
        contextPath: `nodes/${childId}.txt`,
        childIds: []
      };
      parent.childIds.push(child.id);
      nodes.push(child);
      this.contexts.set(child.id, childSpec.context);
      await this.buildChildren(child, nodes, hierarchy, validations);
    }
    this.emit({ type: 'node_completed', nodeId: parent.id, childCount: parent.childIds.length });
  }

  private async queryNode(node: NodeRecord, question: string): Promise<QueryResult> {
    if (!this.manifest) throw new Error('Tree not ready');
    const context = this.contexts.get(node.id) ?? '';
    const children = node.childIds.map((id) => this.manifest!.nodes.find((n) => n.id === id)).filter((n): n is NodeRecord => Boolean(n));
    const childResults = [] as Array<{ node: NodeRecord; result: QueryResult }>;
    for (const child of children) childResults.push({ node: child, result: await this.queryNode(child, question) });
    const user = `QUESTION:\n${question}\n\nOWN CONTEXT:\n${context}\n\nCHILD ANSWERS:\n${childResults.map((r) => `${r.node.title}: ${r.result.answer}\nReasoning: ${r.result.reasoning}`).join('\n\n')}`;
    const response = await retry(() => this.connector.complete([
      { role: 'system', content: queryPrompt(node.role) },
      { role: 'user', content: user }
    ]), 3);
    return parseJsonObject<QueryResult>(response);
  }

  private async persist(): Promise<void> {
    if (!this.manifest) return;
    const root = path.join(this.dataDir, 'trees', this.manifest.id);
    await mkdir(path.join(root, 'nodes'), { recursive: true });
    await writeFile(path.join(root, 'source.txt'), this.options.fullData, 'utf8');
    for (const node of this.manifest.nodes) {
      await writeFile(path.join(root, node.contextPath), this.contexts.get(node.id) ?? '', 'utf8');
    }
    await writeFile(path.join(root, 'manifest.json'), JSON.stringify(this.manifest, null, 2), 'utf8');
  }

  private emit(event: TreeEvent): void { this.onEvent?.(event); }
}
