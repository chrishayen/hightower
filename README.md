# Hightower T2X

A general-purpose hierarchical decomposition system for large text inputs. It discovers a hierarchy at the root, recursively constructs a non-overlapping tree of literal context slices, persists the tree to disk, visualizes it with React Flow, and queries every leaf bottom-up through strictly grounded OpenAI-compatible agents.

## Features

- Node/TypeScript library: `HierarchicalTree`
- OpenAI-compatible `/v1/chat/completions` connector loaded from `.env`
- Works with OpenAI-compatible local servers such as vLLM, LM Studio, and Ollama-compatible endpoints
- Root-only hierarchy discovery with 3 discovery agents
- Recursive construction to the discovered hierarchy depth
- Literal child context slices using offsets; never summaries
- Deterministic validation for offsets, ordering, non-overlap, and uncovered meaningful text warnings
- Parent/root aggregation of child answers; children never communicate with siblings
- Strict context-only grounding prompt tested in `tests/core/prompts.test.ts`
- Disk persistence under `data/trees/<treeId>/`
- HTTP API, background build jobs, SSE progress, and React Flow visualization
- Mock connector for deterministic tests

## Setup

```bash
npm install
cp .env.example .env
```

Edit `.env`:

```env
OPENAI_BASE_URL=http://localhost:1234/v1
OPENAI_API_KEY=not-needed-for-local
OPENAI_MODEL=gpt-4o-mini
DISCOVERY_AGENT_COUNT=3
DATA_DIR=./data
PORT=8787
```

## Development

```bash
npm test
npm run build
npm run dev
```

Open <http://localhost:8787> after starting the server. For Vite frontend hot reload, run `npx vite --host 0.0.0.0` separately and use its dev URL; API calls proxy to the server.

## Library API

```ts
import { HierarchicalTree, OpenAICompatibleConnector } from './src/lib';

const tree = new HierarchicalTree({
  problemStatement: 'Decompose this document into its natural hierarchy.',
  fullData: await fs.promises.readFile('book.txt', 'utf8'),
  apiConfig: {
    baseUrl: process.env.OPENAI_BASE_URL!,
    apiKey: process.env.OPENAI_API_KEY!,
    model: process.env.OPENAI_MODEL!
  },
  dataDir: './data'
});

const manifest = await tree.build();
const result = await tree.query('What are the main claims?');
console.log(result.answer);
console.log(result.reasoning);
```

## HTTP API

- `POST /api/trees` — start a background build job
- `GET /api/jobs/:id` — inspect job status
- `GET /api/jobs/:id/events` — stream SSE build events
- `GET /api/trees` — list persisted trees
- `GET /api/trees/:id` — load a persisted tree manifest
- `POST /api/trees/:id/query` — query the root; returns `{ answer, reasoning }`

## Persistence Layout

```text
data/
  trees/
    <treeId>/
      manifest.json
      source.txt
      nodes/
        root.txt
        root-1.txt
        root-1-1.txt
```

## Important Design Constraints

- No artificial max depth, max children, or max input limit is imposed by the app.
- Provider/model context limits may still fail; failures are retried 3 times and then surfaced clearly.
- Child contexts are exact substrings of parent context and do not overlap.
- The root determines the hierarchy up front; construction follows that hierarchy downward.
- Nodes retain their assigned full context for validation and parent aggregation.
