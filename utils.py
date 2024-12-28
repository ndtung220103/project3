"""
sqlite and enip use name (string) and pid (int) has key and the state stores
values as strings.

Actuator tags are redundant, we will use only the XXX_XXX_OPEN tag ignoring
the XXX_XXX_CLOSE with the following convention:
    - 0 = error
    - 1 = off
    - 2 = on

sqlite uses float keyword and cpppo use REAL keyword.
"""

from minicps.utils import build_debug_logger

swat = build_debug_logger(
    name=__name__,
    bytes_per_file=10000,
    rotating_files=2,
    lformat='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    ldir='logs/',
    suffix='')

TANK_SECTION = 1.5             # m^2

IP = {
    'plc1': '192.168.1.10',
    'hmi': '192.168.1.20',
    'attacker': '192.168.1.77',
}

NETMASK = '/24'

MAC = {
    'plc1': '00:1D:9C:C7:B0:10',
    'hmi': '00:1D:9C:C8:BC:20',
    'attacker': 'AA:AA:AA:AA:AA:AA',
}


# others
# TODO
PLC1_DATA = {
    'TODO': 'TODO',
}
# TODO
HMI_DATA = {
    'TODO': 'TODO',
}



# SPHINX_SWAT_TUTORIAL PLC1 UTILS(
PLC1_ADDR = IP['plc1']
PLC1_TAGS = (
    ('level', 'REAL'),
    ('pump', 'INT'),
    ('alert', 'INT'),
)
PLC1_SERVER = {
    'address': PLC1_ADDR,
    'tags': PLC1_TAGS
}
PLC1_PROTOCOL = {
    'name': 'enip',
    'mode': 1,
    'server': PLC1_SERVER
}
# SPHINX_SWAT_TUTORIAL PLC1 UTILS)

HMI_ADDR = IP['hmi']
HMI_PROTOCOL = {
    'name': 'enip',
    'mode': 0,
    'server': None
}

# state {{{1
# SPHINX_SWAT_TUTORIAL STATE(
PATH = 'project3_db.sqlite'
NAME = 'project3'

STATE = {
    'name': NAME,
    'path': PATH
}
# SPHINX_SWAT_TUTORIAL STATE)

SCHEMA = """
CREATE TABLE project3 (
    name              TEXT NOT NULL,
    value             TEXT,
    PRIMARY KEY (name)
);
"""

SCHEMA_INIT = """
    INSERT INTO project3 VALUES ('level', '1');
    INSERT INTO project3 VALUES ('pump', '1');
"""
