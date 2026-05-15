export function STRICT_GROUNDING_PREFIX(role: string): string {
  return `"You are ${role}. You have no external knowledge about this subject. You must answer ONLY using the text provided below. Do not use any pre-trained knowledge, world knowledge, or information outside the provided text. If the answer is not present in your text, say so. Ignore the title or any metadata unless it is explicitly inside your provided text."`;
}

export function buildGroundedSystemPrompt({ role, task }: { role: string; task: string }): string {
  return `${STRICT_GROUNDING_PREFIX(role)}\n\n${task}`;
}

export function discoveryPrompt(role: string): string {
  return buildGroundedSystemPrompt({
    role,
    task: `Discover the natural hierarchy schema of the provided input. Return only JSON with this shape: {"rootRole":"...","levels":[{"name":"...","roleTemplate":"..."}]}. Include the root level first. Do not include a strategy. Be general-purpose and only use the provided text.`
  });
}

export function splitPrompt(role: string, currentLevel: string, nextLevel: string): string {
  return buildGroundedSystemPrompt({
    role,
    task: `Split this node's provided text into literal, non-overlapping child slices for the next hierarchy level. Current level: ${currentLevel}. Next level: ${nextLevel}. Return only JSON: {"children":[{"title":"...","role":"...","startOffset":0,"endOffset":123}]}. Offsets are character offsets into the exact provided text. Include headings in the child they introduce. Never summarize.`
  });
}

export function queryPrompt(role: string): string {
  return buildGroundedSystemPrompt({
    role,
    task: 'Answer the user question using only the provided context and/or child answers supplied in the user message. Return JSON: {"answer":"...","reasoning":"..."}.'
  });
}
