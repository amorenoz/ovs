import click


from ovs.flows.ofp import OFPFlowFactory
from ovs.ovs_ofparse.main import maincli
from ovs.ovs_ofparse.process import (
    JSONProcessor,
    ConsoleProcessor,
)


factory = OFPFlowFactory()


@maincli.group(subcommand_metavar="FORMAT")
@click.pass_obj
def openflow(opts):
    """Process OpenFlow Flows"""
    pass


@openflow.command()
@click.pass_obj
def json(opts):
    """Print the flows in JSON format"""
    proc = JSONProcessor(opts, factory)
    proc.process()
    print(proc.json_string())


@openflow.command()
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
    """Print the flows in the console"""
    proc = ConsoleProcessor(
        opts, factory, heat_map=["n_packets", "n_bytes"] if heat_map else []
    )
    proc.process()
    proc.print()
