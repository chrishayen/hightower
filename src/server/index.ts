import express from 'express';
import path from 'node:path';
import { loadConfig } from './config';
import { JobManager } from './jobManager';

const config = loadConfig();
const app = express();
const jobs = new JobManager(config.dataDir, config.apiConfig);

app.use(express.json({ limit: '200mb' }));

app.post('/api/trees', (req, res) => {
  const { problemStatement, fullData } = req.body as { problemStatement?: string; fullData?: string };
  if (!problemStatement || !fullData) return res.status(400).json({ error: 'problemStatement and fullData are required' });
  const job = jobs.startBuild(problemStatement, fullData);
  res.status(202).json(job);
});

app.get('/api/jobs/:id', (req, res) => {
  const job = jobs.getJob(req.params.id);
  if (!job) return res.status(404).json({ error: 'job not found' });
  res.json(job);
});

app.get('/api/jobs/:id/events', (req, res) => {
  const job = jobs.getJob(req.params.id);
  if (!job) return res.status(404).end();
  res.setHeader('content-type', 'text/event-stream');
  res.setHeader('cache-control', 'no-cache');
  res.setHeader('connection', 'keep-alive');
  const send = (event: unknown) => res.write(`data: ${JSON.stringify(event)}\n\n`);
  job.events.forEach(send);
  const listener = (event: unknown) => send(event);
  jobs.events.on(req.params.id, listener);
  req.on('close', () => jobs.events.off(req.params.id, listener));
});

app.get('/api/trees', async (_req, res) => res.json(await jobs.listKnownTrees()));

app.get('/api/trees/:id', async (req, res) => {
  try { res.json((await jobs.loadTree(req.params.id)).snapshot()); }
  catch (err) { res.status(404).json({ error: err instanceof Error ? err.message : String(err) }); }
});

app.post('/api/trees/:id/query', async (req, res) => {
  try {
    const { question } = req.body as { question?: string };
    if (!question) return res.status(400).json({ error: 'question is required' });
    res.json(await jobs.query(req.params.id, question));
  } catch (err) { res.status(500).json({ error: err instanceof Error ? err.message : String(err) }); }
});

const clientDir = path.resolve('dist/client');
app.use(express.static(clientDir));
app.get(/.*/, (_req, res) => res.sendFile(path.join(clientDir, 'index.html')));

app.listen(config.port, () => console.log(`hightower listening on http://localhost:${config.port}`));
