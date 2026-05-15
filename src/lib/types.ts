export interface ApiConfig {
  baseUrl: string;
  apiKey: string;
  model: string;
}

export interface HierarchyLevel {
  name: string;
  roleTemplate?: string;
}

export interface HierarchySchema {
  rootRole: string;
  levels: HierarchyLevel[];
}

export interface ChildSliceSpec {
  id?: string;
  title: string;
  role?: string;
  level?: string;
  startOffset: number;
  endOffset: number;
}

export interface NodeRecord {
  id: string;
  parentId: string | null;
  title: string;
  role: string;
  level: string;
  levelIndex: number;
  startOffset: number;
  endOffset: number;
  contextPath: string;
  childIds: string[];
  validation?: ValidationResult;
}

export interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

export interface TreeManifest {
  id: string;
  problemStatement: string;
  hierarchy: HierarchySchema;
  rootNodeId: string;
  nodes: NodeRecord[];
  validation: ValidationResult;
  createdAt: string;
  updatedAt: string;
}

export interface ChatMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

export interface AgentConnector {
  complete(messages: ChatMessage[], options?: { model?: string; temperature?: number }): Promise<string>;
}

export interface QueryResult {
  answer: string;
  reasoning: string;
}

export type TreeEvent =
  | { type: 'job_started'; treeId: string }
  | { type: 'discovery_started'; agentCount: number }
  | { type: 'discovery_completed'; hierarchy: HierarchySchema }
  | { type: 'node_started'; nodeId: string; title: string; level: string }
  | { type: 'node_completed'; nodeId: string; childCount: number }
  | { type: 'validation_failed'; nodeId?: string; errors: string[] }
  | { type: 'job_completed'; treeId: string }
  | { type: 'job_failed'; error: string };
