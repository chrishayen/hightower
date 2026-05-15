import { EventEmitter } from 'node:events';
import { HierarchicalTree, OpenAICompatibleConnector, type ApiConfig, type QueryResult, type TreeEvent, type TreeManifest } from '../lib';

export type JobStatus = 'queued' | 'running' | 'completed' | 'failed';

export interface BuildJob {
  id: string;
  status: JobStatus;
  events: TreeEvent[];
  treeId?: string;
  error?: string;
}

export class JobManager {
  private jobs = new Map<string, BuildJob>();
  private trees = new Map<string, HierarchicalTree>();
  readonly events = new EventEmitter();

  constructor(private readonly dataDir: string, private readonly apiConfig: ApiConfig) {}

  startBuild(problemStatement: string, fullData: string): BuildJob {
    const job: BuildJob = { id: crypto.randomUUID(), status: 'queued', events: [] };
    this.jobs.set(job.id, job);
    void this.runBuild(job, problemStatement, fullData);
    return job;
  }

  getJob(id: string): BuildJob | undefined { return this.jobs.get(id); }

  async loadTree(id: string): Promise<HierarchicalTree> {
    const existing = this.trees.get(id);
    if (existing) return existing;
    const tree = await HierarchicalTree.load(id, { dataDir: this.dataDir, connector: new OpenAICompatibleConnector(this.apiConfig) });
    this.trees.set(id, tree);
    return tree;
  }

  async listKnownTrees(): Promise<TreeManifest[]> {
    const { readdir, readFile } = await import('node:fs/promises');
    const path = await import('node:path');
    const root = path.join(this.dataDir, 'trees');
    try {
      const dirs = await readdir(root, { withFileTypes: true });
      const manifests = await Promise.all(dirs.filter((d) => d.isDirectory()).map(async (d) => JSON.parse(await readFile(path.join(root, d.name, 'manifest.json'), 'utf8')) as TreeManifest));
      return manifests.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
    } catch { return []; }
  }

  async query(treeId: string, question: string): Promise<QueryResult> {
    const tree = await this.loadTree(treeId);
    return tree.query(question);
  }

  private async runBuild(job: BuildJob, problemStatement: string, fullData: string): Promise<void> {
    job.status = 'running';
    const record = (event: TreeEvent) => {
      job.events.push(event);
      this.events.emit(job.id, event);
    };
    try {
      const tree = new HierarchicalTree({ problemStatement, fullData, apiConfig: this.apiConfig, dataDir: this.dataDir, connector: new OpenAICompatibleConnector(this.apiConfig), onEvent: record });
      const manifest = await tree.build();
      job.status = 'completed';
      job.treeId = manifest.id;
      this.trees.set(manifest.id, tree);
    } catch (err) {
      job.status = 'failed';
      job.error = err instanceof Error ? err.message : String(err);
      record({ type: 'job_failed', error: job.error });
    }
  }
}
