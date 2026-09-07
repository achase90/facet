import { Pipe, PipeTransform } from '@angular/core';

/**
 * Whether one photo path counts as selected, under either selection scope.
 *
 * A gallery selection is either an explicit set of paths or "the whole filtered
 * view minus a few" — and a card cannot read the second off `selectedPaths`,
 * which is empty there. A pipe rather than a component method because a method
 * call in a template re-runs for every card on every change-detection pass;
 * this recomputes only when one of the two Sets is replaced, which is how the
 * store mutates them.
 */
@Pipe({ name: 'isSelected', standalone: true, pure: true })
export class IsSelectedPipe implements PipeTransform {
  transform(
    path: string,
    viewScoped: boolean,
    selected: ReadonlySet<string>,
    excluded: ReadonlySet<string>,
  ): boolean {
    return viewScoped ? !excluded.has(path) : selected.has(path);
  }
}
