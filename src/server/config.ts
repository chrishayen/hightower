import dotenv from 'dotenv';
import type { ApiConfig } from '../lib';

dotenv.config();

export interface AppConfig {
  port: number;
  dataDir: string;
  apiConfig: ApiConfig;
}

export function loadConfig(): AppConfig {
  return {
    port: Number(process.env.PORT ?? 8787),
    dataDir: process.env.DATA_DIR ?? './data',
    apiConfig: {
      baseUrl: process.env.OPENAI_BASE_URL ?? 'http://localhost:1234/v1',
      apiKey: process.env.OPENAI_API_KEY ?? 'not-needed-for-local',
      model: process.env.OPENAI_MODEL ?? 'gpt-4o-mini'
    }
  };
}
