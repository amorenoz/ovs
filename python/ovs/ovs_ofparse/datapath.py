import click
from rich.tree import Tree
from rich.text import Text
from rich.style import Style

from ovs.ovs_ofparse.main import maincli
from ovs.flows.odp import ODPFlowFactory
from ovs.ovs_ofparse.process import (
    FlowProcessor,
    JSONProcessor,
    ConsoleProcessor,
)
from ovs.ovs_ofparse.console import (
    ConsoleFormatter,
    ConsoleBuffer,
    print_context,
    hash_pallete,
    heat_pallete,
    file_header,
)
from ovs.ovs_ofparse.dp_tree import FlowTree, FlowElem

factory = ODPFlowFactory()


@maincli.group(subcommand_metavar="FORMAT")
@click.pass_obj
def datapath(opts):
    """Process DPIF Flows"""
    pass


@datapath.command()
@click.pass_obj
def json(opts):
    """Print the flows in JSON format"""
    proc = JSONProcessor(opts, factory)
    proc.process()
    print(proc.json_string())


@datapath.command()
@click.option(
    "-h",
    "--heat-map",
    is_flag=True,
    default=False,
    show_default=True,
    help="Create heat-map with packet and byte counters",
)
@click.pass_obj
def console(opts, heat_map):
    """Print the flows with some style"""
    proc = ConsoleProcessor(
        opts, factory, heat_map=["packets", "bytes"] if heat_map else []
    )
    proc.process()
    proc.print()


@datapath.command()
@click.option(
    "-h",
    "--heat-map",
    is_flag=True,
    default=False,
    show_default=True,
    help="Create heat-map with packet and byte counters",
)
@click.pass_obj
def logic(opts, heat_map):
    """Print the flows in a tree based on the 'recirc_id'"""
    processor = ConsoleTreeProcessor(opts, factory)
    processor.process()
    processor.print(heat_map)


class ConsoleTreeProcessor(FlowProcessor):
    def __init__(self, opts, factory):
        super().__init__(opts, factory)
        self.data = dict()
        self.ofconsole = ConsoleFormatter(self.opts)

        # Generate a color pallete for cookies
        recirc_style_gen = hash_pallete(
            hue=[x / 50 for x in range(0, 50)], saturation=[0.7], value=[0.8]
        )

        style = self.ofconsole.style
        style.set_default_value_style(Style(color="bright_black"))
        style.set_key_style("output", Style(color="green"))
        style.set_value_style("output", Style(color="green"))
        style.set_value_style("recirc", recirc_style_gen)
        style.set_value_style("recirc_id", recirc_style_gen)

    def start_file(self, name, filename):
        self.tree = ConsoleTree(self.ofconsole, self.opts)

    def process_flow(self, flow, name):
        self.tree.add(flow)

    def process(self):
        super().process(False)

    def stop_file(self, name, filename):
        self.data[name] = self.tree

    def print(self, heat_map):
        for name, tree in self.data.items():
            self.ofconsole.console.print("\n")
            self.ofconsole.console.print(file_header(name))
            tree.build()
            if self.opts.get("filter"):
                tree.filter(self.opts.get("filter"))
            tree.print(heat_map)


class ConsoleTree(FlowTree):
    """ConsoleTree is a FlowTree that prints the tree in a console

    Args:
        console (ConsoleFormatter): console to use for printing
        opts (dict): Options dictionary
    """

    class ConsoleElem(FlowElem):
        def __init__(self, flow=None, is_root=False):
            self.tree = None
            super(ConsoleTree.ConsoleElem, self).__init__(
                flow, is_root=is_root
            )

    def __init__(self, console, opts):
        self.console = console
        self.root = self.ConsoleElem(is_root=True)
        self.opts = opts
        super(ConsoleTree, self).__init__()

    def _new_elem(self, flow, _):
        """Override _new_elem to provide ConsoleElems"""
        return self.ConsoleElem(flow)

    def _append_to_tree(self, elem, parent):
        """Callback to be used for FlowTree._build
        Appends the flow to the rich.Tree
        """
        if elem.is_root:
            elem.tree = Tree("Datapath Flows (logical)")
            return

        buf = ConsoleBuffer(Text())
        highlighted = None
        if self.opts.get("highlight"):
            result = self.opts.get("highlight").evaluate(elem.flow)
            if result:
                highlighted = result.kv
        self.console.format_flow(buf, elem.flow, highlighted)
        elem.tree = parent.tree.add(buf.text)

    def print(self, heat=False):
        """Print the Flow Tree
        Args:
            heat (bool): Optional; whether heat-map style shall be applied
        """
        if heat:
            for field in ["packets", "bytes"]:
                values = []
                for flow_list in self._flows.values():
                    values.extend([f.info.get(field) or 0 for f in flow_list])
                self.console.style.set_value_style(
                    field, heat_pallete(min(values), max(values))
                )
        self.traverse(self._append_to_tree)
        with print_context(self.console.console, self.opts):
            self.console.console.print(self.root.tree)
