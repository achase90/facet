import { IsSelectedPipe } from './selection.pipe';

describe('IsSelectedPipe', () => {
  const pipe = new IsSelectedPipe();
  const selected = new Set(['/a.jpg']);
  const excluded = new Set(['/b.jpg']);

  describe('path scope', () => {
    it('reads membership of the explicit selection', () => {
      expect(pipe.transform('/a.jpg', false, selected, excluded)).toBe(true);
      expect(pipe.transform('/c.jpg', false, selected, excluded)).toBe(false);
    });

    it('ignores the exclusion list, which only exists under view scope', () => {
      expect(pipe.transform('/b.jpg', false, selected, excluded)).toBe(false);
    });
  });

  describe('view scope', () => {
    // Everything the filters match is selected, so the Set that matters is the
    // one naming what the user unticked -- selectedPaths is empty there.
    it('treats every photo as selected unless it was unticked', () => {
      expect(pipe.transform('/c.jpg', true, new Set(), excluded)).toBe(true);
      expect(pipe.transform('/b.jpg', true, new Set(), excluded)).toBe(false);
    });

    it('does not fall back to the path selection', () => {
      expect(pipe.transform('/a.jpg', true, selected, new Set(['/a.jpg']))).toBe(false);
    });
  });
});
