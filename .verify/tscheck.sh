#!/bin/sh
# Type-check the frontend without installing the real toolchain.
#
# The sandbox has a global tsc but no node_modules for this project and no
# network to fetch them, so React and dygraphs are stubbed. The stubs are
# deliberately strict — an earlier, looser version hid a real arity bug in a
# dygraphs callback — and `strict` stays on so noImplicitAny still bites.
#
# Rebuilt from scratch each run because /tmp does not survive a restart.
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK=/tmp/tscheck
TSC=/usr/local/lib/node_modules_global/lib/node_modules/typescript/bin/tsc

mkdir -p "$WORK/src" "$WORK/node_modules/dygraphs"

cat > "$WORK/tsconfig.json" <<'EOF'
{ "compilerOptions": { "target":"ES2020","lib":["ES2020","DOM","DOM.Iterable"],
  "module":"ESNext","moduleResolution":"bundler","jsx":"preserve","esModuleInterop":true,
  "strict":true,"noEmit":true,"skipLibCheck":true,"isolatedModules":true }, "include":["src"] }
EOF

cat > "$WORK/src/stubs.d.ts" <<'EOF'
interface StubMouseEvent<T = any> {
  altKey: boolean; ctrlKey: boolean; shiftKey: boolean; metaKey: boolean;
  currentTarget: T; target: any; preventDefault(): void; stopPropagation(): void;
}
interface StubChangeEvent<T = any> { target: T; currentTarget: T; }
interface StubUIEvent<T = any> { target: T; currentTarget: T; }
interface StubCommonProps {
  className?: string;
  style?: { [k: string]: string | number | undefined };
  title?: string; key?: any; children?: any;
  onClick?: (e: StubMouseEvent) => void;
  onScroll?: (e: StubUIEvent<{ scrollTop: number }>) => void;
  [k: string]: any;
}
declare namespace JSX {
  interface IntrinsicAttributes { key?: any }
  interface Element {}
  interface ElementChildrenAttribute { children: {} }
  interface IntrinsicElements {
    input: StubCommonProps & {
      value?: string | number; checked?: boolean; disabled?: boolean;
      onChange?: (e: StubChangeEvent<{ value: string; checked: boolean; files?: any[] | null }>) => void;
    };
    select: StubCommonProps & {
      value?: string | number; disabled?: boolean;
      onChange?: (e: StubChangeEvent<{ value: string }>) => void;
    };
    option: StubCommonProps & { value?: string | number };
    button: StubCommonProps & { disabled?: boolean };
    div: StubCommonProps & { ref?: any };
    td: StubCommonProps & { colSpan?: number };
    [elem: string]: StubCommonProps;
  }
}
declare module "react" {
  export type ReactNode = any;
  export type MouseEvent<T = any> = StubMouseEvent<T>;
  export type ChangeEvent<T = any> = StubChangeEvent<T>;
  export function useState<S>(initial: S | (() => S)): [S, (v: S | ((prev: S) => S)) => void];
  export function useEffect(fn: () => void | (() => void), deps?: readonly any[]): void;
  export function useMemo<T>(fn: () => T, deps: readonly any[]): T;
  export function useRef<T>(v: T): { current: T };
  export const Fragment: any; export const StrictMode: any;
  const React: any; export default React;
}
declare module "react-dom/client" { const x: any; export default x; }
declare module "dygraphs/dist/dygraph.css";
declare module "*.css";
EOF

cat > "$WORK/node_modules/dygraphs/package.json" <<'EOF'
{"name":"dygraphs","version":"2.2.1","types":"index.d.ts"}
EOF

cat > "$WORK/node_modules/dygraphs/index.d.ts" <<'EOF'
// Stand-in for @types/dygraphs, which cannot be fetched here. Declares the
// members this app uses with real signatures, so noImplicitAny stays meaningful
// for the app's own code rather than being switched off wholesale.
declare class Dygraph {
  constructor(el: HTMLElement, data: any, opts?: Dygraph.Options);
  resize(): void;
  updateOptions(o: Dygraph.Options, blockRedraw?: boolean): void;
  destroy(): void;
  xAxisRange(): [number, number];
  yAxisRange(idx?: number): [number, number];
  toDomCoords(x: number, y: number, axis?: number): [number, number];
  toDataCoords(x: number, y: number, axis?: number): [number, number];
  toDataXCoord(x: number): number;
  toDataYCoord(y: number, axis?: number): number;
  getArea(): { x: number; y: number; w: number; h: number };
  isZoomed(axis?: "x" | "y"): boolean;
  resetZoom(): void;
  setVisibility(seriesIndex: number | boolean[], visible?: boolean): void;
  numRows(): number;
  numColumns(): number;
  getValue(row: number, col: number): any;
  setSelection(row: number | false, seriesName?: string): void;
  clearSelection(): void;
  getOption(name: string, seriesName?: string): any;
}
declare namespace Dygraph {
  interface Options {
    [key: string]: any;
    highlightCallback?: (
      event: MouseEvent, x: number, points: any[], row: number, seriesName: string
    ) => void;
    unhighlightCallback?: (event: MouseEvent) => void;
    drawCallback?: (g: Dygraph, isInitial: boolean) => void;
    zoomCallback?: (minX: number, maxX: number, yRanges: [number, number][]) => void;
    clickCallback?: (event: MouseEvent, x: number, points: any[]) => void;
    pointClickCallback?: (event: MouseEvent, point: any) => void;
    drawPointCallback?: (
      g: Dygraph, seriesName: string, ctx: CanvasRenderingContext2D,
      cx: number, cy: number, color: string, pointSize: number
    ) => void;
    underlayCallback?: (ctx: CanvasRenderingContext2D, area: any, g: Dygraph) => void;
    axes?: Record<string, any>;
    labels?: string[];
  }
}
export = Dygraph;
EOF

cp "$ROOT/frontend/src/App.tsx" "$WORK/src/App.tsx"
[ -f "$ROOT/frontend/src/main.tsx" ] && cp "$ROOT/frontend/src/main.tsx" "$WORK/src/main.tsx"

node "$TSC" -p "$WORK/tsconfig.json" && echo "tsc: clean"
