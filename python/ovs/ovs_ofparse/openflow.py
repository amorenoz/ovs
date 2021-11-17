import click


from ovs.flows.ofp import OFPFlowFactory
from ovs.ovs_ofparse.main import maincli
from ovs.ovs_ofparse.process import (
    JSONProcessor,
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
