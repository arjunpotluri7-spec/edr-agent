import type { TreeNode } from "../types";
import { basename } from "../format";

export function ProcessTree({ nodes }: { nodes: TreeNode[] }) {
  return (
    <section aria-labelledby="tree-h">
      <h3 id="tree-h">Process tree</h3>
      <ul className="tree">
        {nodes.map((n) => (
          <li key={n.pid} style={{ paddingLeft: `${n.depth * 1.25}rem` }}>
            <code>{basename(n.image) || "(unknown image)"}</code>{" "}
            <span className="muted">pid {n.pid}</span>
            {n.command_line && <div className="cmd">{n.command_line}</div>}
          </li>
        ))}
      </ul>
    </section>
  );
}
