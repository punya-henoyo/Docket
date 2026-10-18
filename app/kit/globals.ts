// Exposes the two helpers a host page needs to colour kit series, without making the
// host import TypeScript: HenoyoKit.paint('critical') -> { fill, stroke, ink, ... }.
import { scheme } from './frontend/src/components/webcomponents/henoyoKit';
import { paintFor } from './frontend/src/components/webcomponents/vizPalette';

(window as unknown as { HenoyoKit: unknown }).HenoyoKit = {
  scheme,
  paint: (key: string, index = 0) => paintFor(key, index, scheme()),
};
