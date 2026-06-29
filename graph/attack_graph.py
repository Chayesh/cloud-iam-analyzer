import networkx as nx
import matplotlib.pyplot as plt


class AttackGraphBuilder:

    def __init__(self, permissions):
        self.permissions = permissions
        self.graph = nx.DiGraph()

    def build_graph(self):

        for user, actions in self.permissions.items():

            # add user node
            self.graph.add_node(user, type="user")

            for action in actions:

                # permission node
                permission_node = action

                self.graph.add_node(permission_node, type="permission")

                # connect user → permission
                self.graph.add_edge(user, permission_node)

                # possible admin impact
                if "iam:" in action:
                    self.graph.add_edge(permission_node, "IAM Privilege")

                if "sts:AssumeRole" in action:
                    self.graph.add_edge(permission_node, "Role Escalation")

                if "AdministratorAccess" in action:
                    self.graph.add_edge(permission_node, "Admin Access")

        return self.graph


    def visualize(self):

        pos = nx.spring_layout(self.graph)

        plt.figure(figsize=(10, 7))

        nx.draw(
            self.graph,
            pos,
            with_labels=True,
            node_color="lightgreen",
            node_size=2500,
            font_size=9,
            arrows=True
        )

        plt.title("Cloud IAM Attack Graph")

        plt.show()