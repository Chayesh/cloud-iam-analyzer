import networkx as nx
import matplotlib.pyplot as plt


def draw_attack_chain(chain):

    G = nx.DiGraph()

    # Create edges between steps
    for i in range(len(chain) - 1):
        G.add_edge(chain[i], chain[i + 1])

    pos = nx.spring_layout(G)

    plt.figure(figsize=(8, 5))

    nx.draw(
        G,
        pos,
        with_labels=True,
        node_size=3000,
        node_color="lightblue",
        font_size=10,
        font_weight="bold",
        arrows=True
    )

    plt.title("Privilege Escalation Attack Path")

    plt.show()