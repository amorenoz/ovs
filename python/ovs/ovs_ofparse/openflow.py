import click


from ovs.flows.ofp import OFPFlowFactory
from ovs.ovs_ofparse.ofp_logic import LogicFlowProcessor
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


@openflow.command()
@click.option(
    "-s",
    "--show-flows",
    is_flag=True,
    default=False,
    show_default=True,
    help="Show the full flows under each logical flow",
)
@click.option(
    "-c",
    "--cookie",
    "cookie_flag",
    is_flag=True,
    default=False,
    show_default=True,
    help="Consider the cookie in the logical flow",
)
@click.option(
    "-h",
    "--heat-map",
    is_flag=True,
    default=False,
    show_default=True,
    help="Create heat-map with packet and byte counters (when -s is used)",
)
@click.pass_obj
def logic(opts, show_flows, cookie_flag, heat_map):
    """
    Print the logical structure of the flows.

    First, sorts the flows based on tables and priorities.
    Then, deduplicates logically equivalent flows: these a flows that match
    on the same set of fields (regardless of the values they match against),
    have the same priority, and actions (regardless of action arguments,
    except in the case of output and recirculate).
    Optionally, the cookie can also be considered to be part of the logical
    flow.
    """
    processor = LogicFlowProcessor(opts, factory, cookie_flag)
    processor.process()
    processor.print(show_flows, heat_map)
