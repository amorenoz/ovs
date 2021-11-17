import click


from ovs.ovs_ofparse.main import maincli


@maincli.group(subcommand_metavar="FORMAT")
@click.pass_obj
def openflow(opts):
    """Process OpenFlow Flows"""
    pass
