import type { AgentConnector, ChatMessage } from '../types';

function userText(messages: ChatMessage[]): string {
  return messages.filter((m) => m.role === 'user').map((m) => m.content).join('\n');
}

export class MockAgentConnector implements AgentConnector {
  async complete(messages: ChatMessage[]): Promise<string> {
    const system = messages.find((m) => m.role === 'system')?.content ?? '';
    const text = userText(messages);
    if (system.includes('Discover the natural hierarchy schema')) {
      return JSON.stringify({ rootRole: 'the entire provided document', levels: [{ name: 'document', roleTemplate: 'the entire document' }, { name: 'section', roleTemplate: '{title}, a section of the document' }] });
    }
    if (system.includes('Split this node')) {
      const marker = 'TEXT:\n';
      const source = text.includes(marker) ? text.slice(text.indexOf(marker) + marker.length) : text;
      const matches = [...source.matchAll(/^##\s+(.+)$/gm)];
      if (matches.length === 0) return JSON.stringify({ children: [] });
      const children = matches.map((match, idx) => {
        const startOffset = match.index ?? 0;
        const endOffset = idx + 1 < matches.length ? (matches[idx + 1].index ?? source.length) : source.length;
        return { title: match[1].trim(), role: `${match[1].trim()}, a section of the document`, startOffset, endOffset };
      });
      return JSON.stringify({ children });
    }
    if (system.includes('Answer the user question')) {
      const colors = [...new Set((text.match(/\b(red|blue|green|yellow|black|white|orange|purple)\b/gi) ?? []).map((s) => s.toLowerCase()))];
      return JSON.stringify({ answer: colors.length ? `The mentioned colors are ${colors.join(', ')}.` : 'The answer is not present in my text.', reasoning: system.includes('the entire') ? 'root aggregated child answers using its context' : 'leaf answered from its assigned context' });
    }
    return '{}';
  }
}
