import click
from ovs.ovs_ofparse.main import maincli

from ovs.flows.odp import ODPFlowFactory
from ovs.ovs_ofparse.process import (
    JSONProcessor,
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
