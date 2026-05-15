import { describe, expect, it } from 'vitest';
import { buildGroundedSystemPrompt, STRICT_GROUNDING_PREFIX } from '../../src/lib/prompts';

describe('grounded prompts', () => {
  it('starts every node prompt with the exact strict grounding instruction', () => {
    const prompt = buildGroundedSystemPrompt({
      role: "Chapter 7 of the book 'XYZ'",
      task: 'Answer the user question.'
    });

    expect(prompt.startsWith("\"You are Chapter 7 of the book 'XYZ'. You have no external knowledge about this subject.")).toBe(true);
    expect(prompt.startsWith(STRICT_GROUNDING_PREFIX("Chapter 7 of the book 'XYZ'"))).toBe(true);
    expect(prompt).toContain('Answer the user question.');
  });
});
