#!/usr/bin/python

import pefile
import sys
import argparse
import os
import pprint
import networkx
import re
from networkx.drawing.nx_agraph import write_dot
import collections
from networkx.algorithms import bipartite


args = argparse.ArgumentParser("Visualize shared hostnames between a directory of malware samples")
args.add_argument("target_path", help="directory with malware samples")
args.add_argument("output_file", help="file to write DOT file to")
args.add_argument("malware_projection", help="file to write DOT file to")
args.add_argument("sectionname_projection", help="file to write DOT file to")
args = args.parse_args()
network = networkx.Graph()

# search the target directory for valid Windows PE executable files
for root, dirs, files in os.walk(args.target_path):
    for path in files:
        # # try opening the file with pefile to see if it's really a PE file
        try:
            pe = pefile.PE(os.path.join(root, path))
        except pefile.PEFormatError:
            continue

        fullpath = os.path.join(root, path)

        pe_name = pefile.PE(fullpath)
        if len(pe_name.sections):
            network.add_node(path, label=path[:32], color='black', penwidth=5, bipartite=0)
        for section in pe_name.sections:
            sname = str(section.Name, 'utf-8').strip()
            network.add_node(sname, label=sname, color='blue',penwidth=10, bipartite=1)
            network.add_edge(sname, path, penwidth=2)
        if len(pe_name.sections):
            print("Extracted secction names from:", path)
            pprint.pprint(pe_name.sections)


# write the dot file to disk
write_dot(network, args.output_file)
malware_name = set(n for n, d in network.nodes(data=True) if d['bipartite'] == 0)
section_name = set(network) - malware_name

# use NetworkX's bipartite network projection function to produce the malware
# and hostname projections
malware_network = bipartite.projected_graph(network, malware_name)
sectionname_network = bipartite.projected_graph(network, section_name)

# write the projected networks to disk as specified by the user
write_dot(malware_network, args.malware_projection)
write_dot(sectionname_network, args.sectionname_projection)
