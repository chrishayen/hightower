import { describe, expect, it } from 'vitest';
import { validateChildSlices } from '../../src/lib/validation';

describe('child slice validation', () => {
  it('accepts exact ordered non-overlapping child offsets and extracts literal context', () => {
    const parent = 'A Title\nAlpha body.\nB Title\nBeta body.';
    const result = validateChildSlices(parent, [
      { id: 'a', title: 'A', startOffset: 0, endOffset: 20 },
      { id: 'b', title: 'B', startOffset: 20, endOffset: parent.length }
    ]);

    expect(result.valid).toBe(true);
    expect(result.children[0].context).toBe('A Title\nAlpha body.\n');
    expect(result.children[1].context).toBe('B Title\nBeta body.');
  });

  it('rejects overlapping children', () => {
    const result = validateChildSlices('abcdefghij', [
      { id: 'a', title: 'A', startOffset: 0, endOffset: 6 },
      { id: 'b', title: 'B', startOffset: 5, endOffset: 10 }
    ]);

    expect(result.valid).toBe(false);
    expect(result.errors.join('\n')).toMatch(/overlap/i);
  });
});
