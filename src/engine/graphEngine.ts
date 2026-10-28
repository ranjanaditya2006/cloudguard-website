import { Principal, Resource, GraphEdge, AttackPath, AttackHop, RiskLevel } from '../types/iam';

export interface GraphNode {
  id: string;
  name: string;
  type: 'User' | 'Role' | 'ServiceAccount' | 'Group' | 'Resource';
  subType?: string;
  isCrownJewel?: boolean;
  sensitivity?: string;
  riskScore?: number;
  riskCategory?: RiskLevel;
  provider: string;
}

export interface AdjacencyItem {
  targetId: string;
  edge: GraphEdge;
}

export class AccessGraphEngine {
  private nodes: Map<string, GraphNode> = new Map();
  private adjList: Map<string, AdjacencyItem[]> = new Map();
  private reverseAdjList: Map<string, AdjacencyItem[]> = new Map();

  constructor(principals: Principal[], resources: Resource[], edges: GraphEdge[]) {
    this.buildGraph(principals, resources, edges);
  }

  private buildGraph(principals: Principal[], resources: Resource[], edges: GraphEdge[]) {
    // Add principals
    for (const p of principals) {
      this.nodes.set(p.id, {
        id: p.id,
        name: p.name,
        type: p.type,
        provider: p.provider,
      });
      this.adjList.set(p.id, []);
      this.reverseAdjList.set(p.id, []);
    }

    // Add resources
    for (const r of resources) {
      this.nodes.set(r.id, {
        id: r.id,
        name: r.name,
        type: 'Resource',
        subType: r.type,
        isCrownJewel: r.isCrownJewel,
        sensitivity: r.sensitivity,
        provider: r.provider,
      });
      this.adjList.set(r.id, []);
      this.reverseAdjList.set(r.id, []);
    }

    // Add edges
    for (const edge of edges) {
      if (this.nodes.has(edge.source) && this.nodes.has(edge.target)) {
        this.adjList.get(edge.source)?.push({ targetId: edge.target, edge });
        this.reverseAdjList.get(edge.target)?.push({ targetId: edge.source, edge });
      }
    }
  }

  public getNodes(): GraphNode[] {
    return Array.from(this.nodes.values());
  }

  public getNode(id: string): GraphNode | undefined {
    return this.nodes.get(id);
  }

  /**
   * Breadth-First Search (BFS) to find attack paths from source to target Crown Jewel
   * Section 6.5 of Academic Synopsis
   */
  public findAttackPaths(sourceId: string, targetId: string, maxHops: number = 6): AttackPath[] {
    const paths: AttackPath[] = [];
    const sourceNode = this.nodes.get(sourceId);
    const targetNode = this.nodes.get(targetId);

    if (!sourceNode || !targetNode || sourceId === targetId) {
      return paths;
    }

    // Queue holds: { currentId, visitedSet, pathHops, edgesTraversed }
    interface BFSState {
      currentId: string;
      visited: string[];
      hops: AttackHop[];
      edges: GraphEdge[];
    }

    const queue: BFSState[] = [
      {
        currentId: sourceId,
        visited: [sourceId],
        hops: [
          {
            nodeId: sourceNode.id,
            nodeName: sourceNode.name,
            nodeType: sourceNode.type,
            edgeLabel: 'Initial Compromise Entrypoint',
          },
        ],
        edges: [],
      },
    ];

    while (queue.length > 0 && paths.length < 5) {
      const current = queue.shift()!;

      if (current.currentId === targetId) {
        // Found path
        const attackPath = this.constructAttackPath(sourceNode, targetNode, current.hops, current.edges);
        paths.push(attackPath);
        continue;
      }

      if (current.hops.length > maxHops) {
        continue;
      }

      const neighbors = this.adjList.get(current.currentId) || [];
      for (const { targetId: nextId, edge } of neighbors) {
        if (!current.visited.includes(nextId)) {
          const nextNode = this.nodes.get(nextId);
          if (nextNode) {
            const nextHop: AttackHop = {
              nodeId: nextNode.id,
              nodeName: nextNode.name,
              nodeType: nextNode.type,
              edgeLabel: edge.label || edge.type.replace(/_/g, ' '),
              transitionPermission: edge.permissions?.[0] || 'sts:AssumeRole',
            };

            queue.push({
              currentId: nextId,
              visited: [...current.visited, nextId],
              hops: [...current.hops, nextHop],
              edges: [...current.edges, edge],
            });
          }
        }
      }
    }

    return paths;
  }

  /**
   * Discovers all Crown Jewels reachable from a given identity
   */
  public getReachableCrownJewels(sourceId: string): { jewelId: string; jewelName: string; shortestHops: number }[] {
    const visited = new Set<string>();
    const queue: { id: string; dist: number }[] = [{ id: sourceId, dist: 0 }];
    visited.add(sourceId);

    const reachable: { jewelId: string; jewelName: string; shortestHops: number }[] = [];

    while (queue.length > 0) {
      const { id, dist } = queue.shift()!;
      const node = this.nodes.get(id);

      if (node && node.isCrownJewel && id !== sourceId) {
        reachable.push({
          jewelId: id,
          jewelName: node.name,
          shortestHops: dist,
        });
      }

      const neighbors = this.adjList.get(id) || [];
      for (const { targetId } of neighbors) {
        if (!visited.has(targetId)) {
          visited.add(targetId);
          queue.push({ id: targetId, dist: dist + 1 });
        }
      }
    }

    return reachable;
  }

  private constructAttackPath(
    source: GraphNode,
    target: GraphNode,
    hops: AttackHop[],
    edges: GraphEdge[]
  ): AttackPath {
    const narrative: string[] = [];
    narrative.push(`Step 1: Attacker obtains initial valid credentials for ${source.type} "${source.name}".`);

    for (let i = 1; i < hops.length; i++) {
      const hop = hops[i];
      const prev = hops[i - 1];
      const edge = edges[i - 1];

      if (edge.type === 'MEMBER_OF') {
        narrative.push(`Step ${i + 1}: Inherits privileges through membership in group "${hop.nodeName}".`);
      } else if (edge.type === 'CAN_ASSUME') {
        narrative.push(
          `Step ${i + 1}: Leverages trust policy to assume elevated role "${hop.nodeName}" via "${hop.transitionPermission || 'sts:AssumeRole'}".`
        );
      } else if (edge.type === 'ATTACHES_POLICY') {
        narrative.push(`Step ${i + 1}: Policy attachment gives high-privilege administrative permissions.`);
      } else {
        narrative.push(`Step ${i + 1}: Traverses to "${hop.nodeName}" using permissions [${edge.permissions?.join(', ') || 'full-access'}].`);
      }
    }

    narrative.push(`Final Compromise: Attacker gains full read/write access to Crown Jewel Resource "${target.name}".`);

    // Determine chokepoint (most critical role assumption or permission in middle of chain)
    const chokepointEdge = edges.find((e) => e.type === 'CAN_ASSUME' || e.type === 'MEMBER_OF') || edges[0];
    const chokepoint = {
      fromNode: chokepointEdge ? this.nodes.get(chokepointEdge.source)?.name || 'Source' : source.name,
      toNode: chokepointEdge ? this.nodes.get(chokepointEdge.target)?.name || 'Target' : target.name,
      vulnerablePermission: chokepointEdge?.permissions?.[0] || 'sts:AssumeRole',
      recommendation: `Sever the trust relationship from ${chokepointEdge ? this.nodes.get(chokepointEdge.source)?.name : 'Source'} to ${chokepointEdge ? this.nodes.get(chokepointEdge.target)?.name : 'Target'} to completely collapse this attack vector.`,
    };

    return {
      id: `path-${source.id}-${target.id}-${hops.length}`,
      sourceId: source.id,
      sourceName: source.name,
      targetId: target.id,
      targetName: target.name,
      hopCount: hops.length - 1,
      hops,
      chokepoint,
      narrative,
      severity: hops.length <= 3 ? 'CRITICAL' : 'HIGH',
    };
  }
}
