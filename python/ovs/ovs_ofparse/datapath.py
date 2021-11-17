import click
from ovs.ovs_ofparse.main import maincli

from ovs.flows.odp import ODPFlowFactory
from ovs.ovs_ofparse.process import (
    JSONProcessor,
    ConsoleProcessor,
)

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
