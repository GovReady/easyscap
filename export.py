#!/usr/bin/python3
#
# easyscap export tool
#
# Converts easyscap YAML into XCCDF/OVAL.
#
# Usage:
# python3 export.py group.yaml output-xccdf.xml output-oval.xml

import sys, collections, re, os, os.path, datetime
import lxml.etree
import rtyaml

from utils import pandoc, expand_tag_name, simple_namespaces_inv

def main():
	# Process command-line arguments.
	if len(sys.argv) < 3:
		print("Usage:", file=sys.stderr)
		print("python3 export.py tgroup.yaml output-oval.xml", file=sys.stderr)
		sys.exit(1)

	filename = sys.argv[1]
	out_oval = sys.argv[2]

	namespaces = {
		None: "http://oval.mitre.org/XMLSchema/oval-definitions-5",
		"oval": "http://oval.mitre.org/XMLSchema/oval-common-5"
		}
	namespaces.update(simple_namespaces_inv)

	oval = lxml.etree.Element(
		"{http://oval.mitre.org/XMLSchema/oval-definitions-5}oval_definitions",
		nsmap=namespaces)

	# metadata
	generator = make_node(oval, "generator")
	make_node(generator, "{http://oval.mitre.org/XMLSchema/oval-common-5}product_name", "easyscap")
	make_node(generator, "{http://oval.mitre.org/XMLSchema/oval-common-5}product_version", "0.0.0.0")
	make_node(generator, "{http://oval.mitre.org/XMLSchema/oval-common-5}schema_version", "5.10")
	make_node(generator, "{http://oval.mitre.org/XMLSchema/oval-common-5}timestamp", datetime.datetime.now().isoformat())

	# create test nodes
	oval_nodes = {
		"definitions": make_node(oval, "definitions"),
		"tests": make_node(oval, "tests"),
		"objects": make_node(oval, "objects"),
		"states": make_node(oval, "states"),
		"variables": make_node(oval, "variables"),

		"definition_count": 0,
		"object_count": 0,
		"state_count": 0,
	}
	process_group(filename, oval_nodes)

	# write output
	with open(out_oval, "w") as f:
		f.write(lxml.etree.tostring(oval, pretty_print=True, encoding=str))

def process_group(filename, oval_nodes):
	yaml = rtyaml.load(open(filename))

	# Process all test definitions in this group.
	for rule in yaml.get("rules", []):
		fn = os.path.join(os.path.dirname(filename), rule + ".yaml")
		process_rule(fn, oval_nodes)

	# Recursively process all subgroups mentioned in this group.
	for subgroup in yaml.get("subgroups", []):
		# Subgroups are specified either as a relative path name, or as a
		# relative directory name in which we look for group.yaml.
		fn = os.path.join(os.path.dirname(filename), subgroup)
		if os.path.exists(fn) and not os.path.isdir(fn):
			process_group(fn, oval_nodes)
			continue

		fn = os.path.join(os.path.dirname(filename), subgroup, "group.yaml")
		if os.path.exists(fn):
			process_group(fn, oval_nodes)
			continue

def process_rule(filename, oval_nodes):
	# A rule is metadata + zero or more tests.

	yaml = rtyaml.load(open(filename))

	# Create the rule definition.
	oval_nodes["definition_count"] += 1
	defnode = make_node(oval_nodes["definitions"], "definition",
		id="oval:easyscap_generated:def:%d" % oval_nodes["definition_count"], version="1")
	defnode.set("class", "compliance")
	defnodemeta = make_node(defnode, "metadata")
	make_node(defnodemeta, "title", yaml["title"])
	affected = make_node(defnodemeta, "affected", family="unix")
	make_node(affected, "platform", "Unknown")
	make_node(defnodemeta, "description", pandoc(yaml["description"], "markdown", "html")) # should be inserted raw, not escaped
	defnodecriteria = None

	# Create OVAL definitions for the variables.
	var_map = { }
	try:
		for key, var in yaml.get("variables", {}).items():
			node = dict_to_node(oval_nodes["variables"], var, oval_nodes=oval_nodes)
			varid = "oval:%s:var:%d" % (yaml["id"], key+1)
			node.set("id", varid)
			var_map[key] = varid
	except Exception as e:
		raise Exception("Error processing rule %s: %s" % (filename, str(e)))

	# Create OVAL definitions for the tests.
	try:
		for i, test in enumerate(yaml.get("tests", [])):
			node = process_test(test, oval_nodes, yaml["id"], i, var_map)

			if defnodecriteria is None:
				defnodecriteria = make_node(defnode, "criteria")
			make_node(defnodecriteria, "criterion", test_ref=node.get('id'))

	except Exception as e:
		raise Exception("Error processing rule %s: %s" % (filename, str(e)))

def process_test(test, oval_nodes, rule_id, test_index, var_map):
	# Create an OVAL definition for the test.

	# The object and state have to be moved into their own parts.
	for key, idslug in (("object", "obj"), ("state", "ste")):
		if key not in test: continue

		# Generate an id.
		oval_nodes[key + "_count"] += 1
		test[key]['id'] = "oval:easyscap_generated:%s:%d" % (idslug, oval_nodes[key + "_count"])

		# Generate an implicit type.
		if "type" not in test[key]:
			if not test.get("type", "").endswith("_test"): raise ValueError("Invalid test type: " + test)
			test[key]["type"] = test["type"][:-4] + key

		dict_to_node(oval_nodes[key+"s"], test[key], var_map=var_map, oval_nodes=oval_nodes)

		test[test["type"].split(":")[0] + ":" + key] = { key + "_ref": test[key]['id'] }

		del test[key]
		

	# Convert the rest.
	try:
		node = dict_to_node(oval_nodes["tests"], test, var_map=var_map, oval_nodes=oval_nodes)
		node.set("id", "oval:%s:tst:%d" % (rule_id, test_index+1))
	except Exception as e:
		raise Exception("Error processing test (%s) in (%s)" % (str(e), rtyaml.dump(test)))
	return node

def dict_to_node(parent, dictobj, default_type=None, var_map=None, oval_nodes=None):
	my_type = dictobj.get("type", default_type)
	if my_type is None: raise Exception("Invalid data: Missing type. (%s)" % rtyaml.dump(dictobj))

	node = make_node(parent, expand_tag_name(my_type))

	for k, v in dictobj.items():
		if k == "type":
			# already handled
			continue

		elif k == "var_ref" and var_map is not None:
			# Re-map variables.
			node.set("var_ref", var_map[v])

		elif k == "object_ref" and isinstance(v, dict) and oval_nodes is not None:
			# Re-create object.
			oval_nodes["object_count"] += 1
			objid = "oval:easyscap_generated:%s:%d" % ('obj', oval_nodes["object_count"])
			n = dict_to_node(oval_nodes["objects"], v, var_map=var_map, oval_nodes=oval_nodes)
			n.set('id', objid)
			node.set(expand_tag_name(k), objid)

		elif expand_tag_name(my_type) == '{http://oval.mitre.org/XMLSchema/oval-definitions-5}filter' and k == "value":
			# Re-create object.
			oval_nodes["state_count"] += 1
			objid = "oval:easyscap_generated:%s:%d" % ('ste', oval_nodes["state_count"])
			n = dict_to_node(oval_nodes["states"], v, var_map=var_map, oval_nodes=oval_nodes)
			n.set('id', objid)
			node.text = objid

		elif k == "value":
			# This content goes right into the node's inner text.
			v, dt = get_data_type(v)
			if dt: node.set("datatype", dt)
			node.text = v

		elif not isinstance(v, dict) and ((":" not in k and "{" not in k and not k.startswith("<")) or k.startswith("@")):
			# This is an attribute.
			if k[0] == "@": k = k[1:]
			node.set(expand_tag_name(k), str(v))

		elif not isinstance(v, dict):
			# This is a simple element.
			v, dt = get_data_type(v)
			if dt:
				dt = { "datatype": dt }
			else:
				dt = { }
			make_node(node, expand_tag_name(k), v, **dt)

		else:
			# This is obviously an element because it has a complex child.
			dict_to_node(node, v, default_type=expand_tag_name(k), oval_nodes=oval_nodes, var_map=var_map)

	return node

def get_data_type(value):
	if isinstance(value, bool):
		return ("true" if value else "false", "boolean")
	if isinstance(value, int):
		return (str(value), "int")
	return value, None

def make_node(parent, tag, text=None, **attrs):
  """Make a node in an XML document."""
  n = lxml.etree.Element(tag)
  parent.append(n)
  n.text = text
  for k, v in attrs.items():
    if v is None: continue
    n.set(k.replace("___", ""), v)
  return n

if __name__ == "__main__":
	main()
