# Copyright (c) 2022,2023 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import click
from rich.style import Style
from rich.text import Text
from rich.tree import Tree

from ovs.flowviz.main import maincli
from ovs.flowviz.console import (
    ConsoleFormatter,
    ConsoleBuffer,
    hash_pallete,
    heat_pallete,
    file_header,
)
from ovs.flowviz.dp_tree import FlowTree, FlowElem
from ovs.flowviz.process import (
    DatapathFactory,
    ConsoleProcessor,
    FileProcessor,
    JSONProcessor,
)


@maincli.group(subcommand_metavar="FORMAT")
@click.pass_obj
def datapath(opts):
    """Process Datapath Flows"""
    pass


class JSONPrint(DatapathFactory, JSONProcessor):
    def __init__(self, opts):
        super().__init__(opts)


@datapath.command()
@click.pass_obj
def json(opts):
    """Print the flows in JSON format"""
    proc = JSONPrint(opts)
    proc.process()
    print(proc.json_string())


class DPConsoleProcessor(DatapathFactory, ConsoleProcessor):
    def __init__(self, opts, heat_map):
        super().__init__(opts, heat_map)


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
    """Print the flows in the console with some style"""
    proc = DPConsoleProcessor(
        opts, heat_map=["packets", "bytes"] if heat_map else []
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
def tree(opts, heat_map):
    """Print the flows in a tree based on the 'recirc_id'"""
    processor = ConsoleTreeProcessor(opts)
    processor.process()
    processor.print(heat_map)


class ConsoleTreeProcessor(DatapathFactory, FileProcessor):
    def __init__(self, opts):
        super().__init__(opts)
        self.data = dict()
        self.ofconsole = ConsoleFormatter(self.opts)

        # Generate a color pallete for cookies
        recirc_style_gen = hash_pallete(
            hue=[x / 50 for x in range(0, 50)], saturation=[0.7], value=[0.8]
        )

        style = self.ofconsole.style
        style.set_default_value_style(Style(color="grey66"))
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
        self.opts = opts
        super(ConsoleTree, self).__init__(root=self.ConsoleElem(is_root=True))

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
        self.console.console.print(self.root.tree)
