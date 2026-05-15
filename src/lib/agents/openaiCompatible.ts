import type { AgentConnector, ApiConfig, ChatMessage } from '../types';

export class OpenAICompatibleConnector implements AgentConnector {
  constructor(private readonly config: ApiConfig) {}

  async complete(messages: ChatMessage[], options?: { model?: string; temperature?: number }): Promise<string> {
    const base = this.config.baseUrl.replace(/\/$/, '');
    const res = await fetch(`${base}/chat/completions`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${this.config.apiKey}`
      },
      body: JSON.stringify({
        model: options?.model ?? this.config.model,
        messages,
        temperature: options?.temperature ?? 0
      })
    });
    if (!res.ok) {
      const body = await res.text();
      throw new Error(`OpenAI-compatible API failed ${res.status}: ${body}`);
    }
    const json = await res.json() as { choices?: Array<{ message?: { content?: string } }> };
    const content = json.choices?.[0]?.message?.content;
    if (!content) throw new Error('OpenAI-compatible API returned no message content');
    return content;
  }
}
