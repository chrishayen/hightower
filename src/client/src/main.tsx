import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import ReactFlow, { Background, Controls, MiniMap, type Edge, type Node } from 'reactflow';
import 'reactflow/dist/style.css';
import './styles.css';

type Manifest = { id: string; rootNodeId: string; hierarchy: { levels: { name: string }[] }; nodes: Array<{ id: string; parentId: string | null; title: string; role: string; level: string; childIds: string[]; validation?: { valid: boolean; errors: string[]; warnings: string[] } }> };
type QueryResult = { answer: string; reasoning: string };

function layout(manifest?: Manifest): { nodes: Node[]; edges: Edge[] } {
  if (!manifest) return { nodes: [], edges: [] };
  const byParent = new Map<string | null, Manifest['nodes']>();
  for (const n of manifest.nodes) byParent.set(n.parentId, [...(byParent.get(n.parentId) ?? []), n]);
  const rfNodes: Node[] = [];
  const edges: Edge[] = [];
  const visit = (id: string, depth: number, x: number): number => {
    const node = manifest.nodes.find((n) => n.id === id)!;
    const kids = byParent.get(id) ?? [];
    let width = Math.max(1, kids.length);
    let childX = x;
    for (const kid of kids) {
      edges.push({ id: `${id}-${kid.id}`, source: id, target: kid.id });
      childX += visit(kid.id, depth + 1, childX) * 260;
    }
    rfNodes.push({ id, position: { x: x * 260, y: depth * 150 }, data: { label: `${node.title}\n${node.level}` }, style: { whiteSpace: 'pre-line', border: node.validation?.valid === false ? '2px solid #ef4444' : '1px solid #64748b', padding: 10, borderRadius: 8 } });
    return width;
  };
  visit(manifest.rootNodeId, 0, 0);
  return { nodes: rfNodes, edges };
}

function App() {
  const [problemStatement, setProblemStatement] = useState('Decompose this input into its natural hierarchy.');
  const [fullData, setFullData] = useState('');
  const [jobId, setJobId] = useState<string>();
  const [events, setEvents] = useState<string[]>([]);
  const [manifest, setManifest] = useState<Manifest>();
  const [question, setQuestion] = useState('');
  const [query, setQuery] = useState<QueryResult>();
  const graph = useMemo(() => layout(manifest), [manifest]);

  useEffect(() => {
    fetch('/api/trees').then((r) => r.json()).then((trees: Manifest[]) => trees[0] && setManifest(trees[0])).catch(() => undefined);
  }, []);

  async function build() {
    setEvents([]); setManifest(undefined); setQuery(undefined);
    const res = await fetch('/api/trees', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ problemStatement, fullData }) });
    const job = await res.json(); setJobId(job.id);
    const source = new EventSource(`/api/jobs/${job.id}/events`);
    source.onmessage = async (msg) => {
      const event = JSON.parse(msg.data);
      setEvents((e) => [...e, JSON.stringify(event)]);
      if (event.type === 'job_completed') { source.close(); setManifest(await fetch(`/api/trees/${event.treeId}`).then((r) => r.json())); }
      if (event.type === 'job_failed') source.close();
    };
  }

  async function ask() {
    if (!manifest) return;
    setQuery(await fetch(`/api/trees/${manifest.id}/query`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ question }) }).then((r) => r.json()));
  }

  return <div className="app">
    <aside>
      <h1>Hightower T2X</h1>
      <label>Problem statement<textarea value={problemStatement} onChange={(e) => setProblemStatement(e.target.value)} /></label>
      <label>Input text<textarea className="input" value={fullData} onChange={(e) => setFullData(e.target.value)} placeholder="Paste .txt/.md/.json text here" /></label>
      <button onClick={build} disabled={!fullData}>Build Tree</button>
      {jobId && <p>Job: {jobId}</p>}
      <h2>Progress</h2><pre>{events.join('\n')}</pre>
      {manifest && <><h2>Query Root</h2><input value={question} onChange={(e) => setQuestion(e.target.value)} placeholder="Ask a question" /><button onClick={ask}>Query</button></>}
      {query && <section><h3>Answer</h3><p>{query.answer}</p><h3>Reasoning</h3><p>{query.reasoning}</p></section>}
    </aside>
    <main>{manifest ? <ReactFlow nodes={graph.nodes} edges={graph.edges} fitView><MiniMap /><Controls /><Background /></ReactFlow> : <div className="empty">Build or load a tree to visualize it.</div>}</main>
  </div>;
}

createRoot(document.getElementById('root')!).render(<App />);
