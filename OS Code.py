import psutil
from collections import defaultdict
import networkx as nx
import matplotlib.pyplot as plt
import tkinter as tk
from tkinter import messagebox, ttk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
class DeadlockDetector:
    def __init__(self):
        self.edges = []
        self.history = []  # Stack to store previous edges for undo functionality

    def add_edge(self, process, resource):
        # Add a directional edge from process to resource
        self.edges.append((process, resource))
        self.history.append(('add', process, resource))  # Record the action in history

    def remove_edge(self, process, resource):
        # Remove the last added edge
        if (process, resource) in self.edges:
            self.edges.remove((process, resource))
            self.history.append(('remove', process, resource))  # Record the action in history

    def undo(self):
        if self.history:
            action, process, resource = self.history.pop()  # Get the last action from history
            if action == 'add':
                self.remove_edge(process, resource)  # Undo by removing the last added edge
            elif action == 'remove':
                self.add_edge(process, resource)  # Undo by adding back the last removed edge
            self.visualize_graph(canvas_frame)

    def detect_deadlock(self):
        G = nx.DiGraph()
        G.add_edges_from(self.edges)
        cycles = list(nx.simple_cycles(G))
        return cycles if cycles else None

    def resolve_deadlocks(self, cycles):
        for cycle in cycles:
            process_to_kill = None
            for node in cycle:
                if node.startswith("P"):
                    process_to_kill = node
                    break
            if process_to_kill:
                messagebox.showinfo("Deadlock Resolved", f"Terminating process {process_to_kill} to break the cycle.")
                self.edges = [(u, v) for u, v in self.edges if u != process_to_kill and v != process_to_kill]

    def visualize_graph(self, canvas_frame):
        G = nx.DiGraph()
        request_edges = []
        assignment_edges = []
        requesting_resources = set()
        assigned_resources = set()
    
        for u, v in self.edges:
            if u.upper().startswith("P"):  # Request: P → R
                request_edges.append((u, v))
                requesting_resources.add(v)
            else:  # Assignment: R → P
                assignment_edges.append((u, v))
                assigned_resources.add(u)
    
        all_resources = requesting_resources.union(assigned_resources)
        G.add_edges_from(request_edges + assignment_edges)
    
        pos = nx.circular_layout(G)
        fig, ax = plt.subplots(figsize=(10, 5), facecolor="#2E2E2E")
        ax.set_facecolor("#2E2E2E")
    
        process_nodes = [n for n in G.nodes if n.upper().startswith("P")]
        resource_requested_only = list(requesting_resources - assigned_resources)
        resource_assigned = list(assigned_resources)
    
        nx.draw_networkx_nodes(G, pos, nodelist=process_nodes, node_color='#4CAF50',
                               node_size=2200, node_shape='o', ax=ax)
        nx.draw_networkx_nodes(G, pos, nodelist=resource_requested_only, node_color='#03A9F4',
                               node_size=1800, node_shape='o', ax=ax)
        nx.draw_networkx_nodes(G, pos, nodelist=resource_assigned, node_color='#FF9800',
                               node_size=2200, node_shape='s', ax=ax)
    
        if request_edges:
            nx.draw_networkx_edges(G, pos, edgelist=request_edges, edge_color='blue',
                                   style='dashed', arrows=True, ax=ax)
        if assignment_edges:
            nx.draw_networkx_edges(G, pos, edgelist=assignment_edges, edge_color='green',
                                   style='solid', arrows=True, ax=ax)
    
        nx.draw_networkx_labels(G, pos, font_color='white', font_size=12, ax=ax)
    
        edge_labels = {}
        for u, v in request_edges:
            edge_labels[(u, v)] = "Request"
        for u, v in assignment_edges:
            edge_labels[(u, v)] = "Assignment"
        nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_color='white', ax=ax)
    
        # Interactivity: show tooltip when hovering over node
        annot = ax.annotate("", xy=(0, 0), xytext=(20, 20), textcoords="offset points",
                            bbox=dict(boxstyle="round", fc="w"),
                            arrowprops=dict(arrowstyle="->"))
        annot.set_visible(False)
    
        node_positions = {node: pos[node] for node in G.nodes}
    
        def update_annot(ind, node_name):
            x, y = node_positions[node_name]
            annot.xy = (x, y)
    
            # Check what message to display
            tooltip_text = ""
            for u, v in request_edges:
                if u == node_name:
                    tooltip_text = f"Process {u} is waiting for {v}"
                elif v == node_name:
                    tooltip_text = f"Resource {v} is requested by {u}"
            for u, v in assignment_edges:
                if u == node_name:
                    tooltip_text = f"Resource {u} is allocated to {v}"
                elif v == node_name:
                    tooltip_text = f"Process {v} holds {u}"
    
            annot.set_text(tooltip_text)
            annot.get_bbox_patch().set_facecolor('#444444')
            annot.get_bbox_patch().set_alpha(0.9)
            annot.get_bbox_patch().set_edgecolor('white')
    
        def hover(event):
            vis = annot.get_visible()
            if event.inaxes == ax:
                for node, (x, y) in node_positions.items():
                    radius = 0.05  # Hover radius
                    if abs(event.xdata - x) < radius and abs(event.ydata - y) < radius:
                        update_annot(None, node)
                        annot.set_visible(True)
                        fig.canvas.draw_idle()
                        return
            if vis:
                annot.set_visible(False)
                fig.canvas.draw_idle()
    
        fig.canvas.mpl_connect("motion_notify_event", hover)
    
        # Clear and render canvas
        for widget in canvas_frame.winfo_children():
            widget.destroy()
    
        canvas = FigureCanvasTkAgg(fig, master=canvas_frame)
        canvas.draw()
        canvas.get_tk_widget().pack()

        def reset(self, canvas_frame):
            self.edges.clear()
            self.history.clear()
            self.visualize_graph(canvas_frame)


# GUI Implementation
def check_deadlock():
    cycles = detector.detect_deadlock()
    if cycles:
        messagebox.showwarning("Deadlock Detected", f"Deadlocks found: {cycles}")
        detector.resolve_deadlocks(cycles)
        status_label.config(text="Deadlocks detected! Resolved by terminating processes.", fg='lightgray')
    else:
        messagebox.showinfo("No Deadlock", "No deadlock detected.")
        status_label.config(text="No deadlock detected.", fg='white')
    detector.visualize_graph(canvas_frame)


def add_process_resource():
    process = process_entry.get().strip()
    resource = resource_entry.get().strip()
    if process and resource:
        detector.add_edge(process, resource)
        process_entry.delete(0, tk.END)
        resource_entry.delete(0, tk.END)
        detector.visualize_graph(canvas_frame)
        listbox.insert(tk.END, f"{process} -> {resource} (Assignment)")
        status_label.config(text=f"Added assignment: {process} -> {resource}", fg='blue')


def request_resource():
    process = process_entry.get().strip()
    resource = resource_entry.get().strip()
    if process and resource:
        # Add resource -> process edge to simulate "resource assigned to process"
        detector.add_edge(resource, process)
        process_entry.delete(0, tk.END)
        resource_entry.delete(0, tk.END)
        detector.visualize_graph(canvas_frame)
        listbox.insert(tk.END, f"{resource} -> {process} (Request)")
        status_label.config(text=f"Resource requested: {resource} -> {process}", fg='orange')


def undo_action():
    detector.undo()
    status_label.config(text="Last action undone.", fg='purple')

def reset_graph():
    detector.reset(canvas_frame)
    listbox.delete(0, tk.END)
    status_label.config(text="Graph has been reset.", fg='red')

detector = DeadlockDetector()

# Creating GUI window
root = tk.Tk()
root.title("Deadlock Detection Tool")
root.geometry("750x650")
root.configure(bg="grey")

style = ttk.Style()

style.configure("Exit.TButton", foreground="yellow")
style.configure("Check.TButton", foreground="Blue")
style.map("Exit.TButton", foreground=[("active", "red")])
style.map("Check.TButton", foreground=[("active", "red")])
style.configure("TButton", font=("Arial", 12), padding=8, background="#4CAF50", foreground="red", borderwidth=1, relief="flat")
style.map("TButton", background=[["active", "#45a049"]])

frame_top = tk.Frame(root, bg="#2E2E2E", padx=10, pady=10)
frame_top.pack(fill=tk.X)

frame_middle = tk.Frame(root, bg="#1E1E1E")
frame_middle.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

frame_bottom = tk.Frame(root, bg="#1E1E1E", padx=10, pady=10)
frame_bottom.pack(fill=tk.X)

tk.Label(frame_top, text="Process:", font=("Arial", 12), bg="#2E2E2E", fg="white").pack(side=tk.LEFT, padx=5)
process_entry = tk.Entry(frame_top, font=("Arial", 12), bg="#444444", fg="white", insertbackground="white", width=15)
process_entry.pack(side=tk.LEFT, padx=5)

tk.Label(frame_top, text="Resource:", font=("Arial", 12), bg="#2E2E2E", fg="white").pack(side=tk.LEFT, padx=5)
resource_entry = tk.Entry(frame_top, font=("Arial", 12), bg="#444444", fg="white", insertbackground="white", width=15)
resource_entry.pack(side=tk.LEFT, padx=5)

add_button = ttk.Button(frame_top, text="Assign Resource", command=add_process_resource)
add_button.pack(side=tk.LEFT, padx=5)

request_button = ttk.Button(frame_top, text="Request Resource", command=request_resource)
request_button.pack(side=tk.LEFT, padx=5)

reset_button = ttk.Button(frame_top, text="Reset", command=reset_graph)
reset_button.pack(side=tk.LEFT, padx=5)

check_button = ttk.Button(frame_top, text="Check Deadlock", command=check_deadlock)
check_button.pack(side=tk.LEFT, padx=5)

undo_button = ttk.Button(frame_top, text="Undo", command=undo_action)
undo_button.pack(side=tk.LEFT, padx=5)

canvas_frame = tk.Frame(frame_middle, bg="#1E1E1E")
canvas_frame.pack(fill=tk.BOTH, expand=True, pady=10)

listbox = tk.Listbox(frame_middle, height=8, font=("Arial", 12), bg="#444444", fg="white", selectbackground="#4CAF50", selectforeground="black")
listbox.pack(fill=tk.X, padx=10, pady=5)

status_label = tk.Label(frame_bottom, text="Status: Ready", font=("Arial", 12), bg="#1E1E1E", fg="white")
status_label.pack()

exit_button = ttk.Button(frame_bottom, text="Exit", command=root.quit)
exit_button.pack()

root.mainloop()
