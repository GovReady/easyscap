#!/usr/bin/python3
#
# easyscap import tool
#
# Converts XCCDF/OVAL into easyscap YAML.
#
# Usage:
# python3 import.py testfile.xml outdir

import sys, collections, re, os, os.path
import lxml.etree
import rtyaml

from utils import pandoc, get_simple_tag_name

def main():
	# Process command-line arguments.
	if len(sys.argv) < 3:
		print("Usage:", file=sys.stderr)
		print("python3 import.py testfile.xml outdir", file=sys.stderr)
		sys.exit(1)

	filename = sys.argv[1]
	outdir = sys.argv[2]

	dom = lxml.etree.parse(filename).getroot()
	if dom.tag == "{http://checklists.nist.gov/xccdf/1.2}Benchmark":
		# This is an XCCDF 1.2 file.
		import_xccdf_12(dom, filename, outdir)
	#elif dom.tag == "{http://oval.mitre.org/XMLSchema/oval-definitions-5}oval_definitions":
	#	# This is an OVAL 5 file.
	#	ret = import_oval(dom)
	else:
		print("Unrecognized XML file format.", file=sys.stderr)

def import_xccdf_12(xccdf, path, outdir):
	# Convert an XCCDF 1.2 file into easyscap format.

	# See which rules are active in which profiles and capture variable refinements.
	rule_profiles = { }
	profile_variable_refinements = { }
	for profile in xccdf.findall("{http://checklists.nist.gov/xccdf/1.2}Profile"):
		# Selected Rules
		for rule in profile.findall("{http://checklists.nist.gov/xccdf/1.2}select"):
			if rule.get("selected") == "true":
				rule_profiles.setdefault(rule.get("idref"), set()).add( profile.get("id") )

		# Variable Refinements
		for refinement in profile.findall("{http://checklists.nist.gov/xccdf/1.2}refine-value"):
			profile_variable_refinements.setdefault(profile.get("id"), {})\
				[refinement.get("idref")] = refinement.get("selector")

	# Process groups.
	process_xccdf_group(xccdf, path, outdir, rule_profiles, [], None)

def process_xccdf_group(xccdf, xccdf_path, outdir, rule_profiles, group_path, drop_id_prefix):
	# Process all of the rules here.
	rules = []
	for rule in xccdf.findall("{http://checklists.nist.gov/xccdf/1.2}Rule"):
		rules.append(process_rule(rule, rule_profiles, xccdf_path, group_path, outdir, drop_id_prefix))
	
	# Process all of the groups here
	groups = []
	for group in xccdf.findall("{http://checklists.nist.gov/xccdf/1.2}Group"):
		# a nice directory name for the group
		g = group.get('id')
		g = re.sub('^xccdf_org\.(.*)\.content_group_(.*)$', r'\1_\2', g)
		if drop_id_prefix and g.startswith(drop_id_prefix):
			g = g[len(drop_id_prefix):]
			child_drop_id_prefix = drop_id_prefix
		elif "_" in g:
			child_drop_id_prefix = g.split("_")[0] + "_"
		else:
			child_drop_id_prefix = None
		groups.append(g)

		process_xccdf_group(group, xccdf_path, outdir, rule_profiles, group_path + [g], child_drop_id_prefix)

	groupdict = collections.OrderedDict([
		("id", xccdf.get("id")),
		("title", xccdf.find("{http://checklists.nist.gov/xccdf/1.2}title").text),
		("description", pandoc(xccdf.find("{http://checklists.nist.gov/xccdf/1.2}description"), 'html', 'markdown')),
		("rules", rules),
		("subgroups", groups),
		])
	fn = os.path.join(*([outdir] + group_path + ['group.yaml']))
	os.makedirs(os.path.dirname(fn), exist_ok=True)
	with open(fn, "w") as f:
		rtyaml.dump(groupdict, f)

def process_rule(rule, rule_profiles, xccdf_path, group_path, outdir, drop_id_prefix):
	# Turn an XCCDF Rule into a Python dict.

	ruledict = collections.OrderedDict([
		("id", rule.get("id")),
		("severity", rule.get("severity")),
		("title", rule.find("{http://checklists.nist.gov/xccdf/1.2}title").text),
		("description", pandoc(rule.find("{http://checklists.nist.gov/xccdf/1.2}description"), 'html', 'markdown')),
		("rationale", pandoc(rule.find("{http://checklists.nist.gov/xccdf/1.2}rationale"), 'html', 'markdown')),
		("references", [node_to_dict(n) for n in rule if n.tag == "{http://checklists.nist.gov/xccdf/1.2}reference"]),
		("crosswalk", [node_to_dict(n) for n in rule if n.tag == "{http://checklists.nist.gov/xccdf/1.2}ident"]),
	])

	## Which profiles is this rule included in?
	# Let's move this to the group definitions to the extent that profiles
	# activate entire groups.
	# TODO: We'll move profiles into separate files.
	#if rule.get("id") in rule_profiles:
	#	ruledict["profiles"] = sorted(rule_profiles[rule.get("id")])

	# The rule's test.
	test = rule.find("{http://checklists.nist.gov/xccdf/1.2}check[@system='http://oval.mitre.org/XMLSchema/oval-definitions-5']")
	if test is not None:
		ref = test.find("{http://checklists.nist.gov/xccdf/1.2}check-content-ref")
		if ref is not None:
			oval = load_oval_file(xccdf_path, ref.get("href"))
			ovalcontent = oval.find(".//*[@id='" + ref.get("name") + "']")
			if ovalcontent is not None:
				criteria = ovalcontent.find('{http://oval.mitre.org/XMLSchema/oval-definitions-5}criteria')
				if criteria is not None:
					ruledict["tests"] = []
					for criterion in criteria.findall('{http://oval.mitre.org/XMLSchema/oval-definitions-5}criterion'):
						ovaltest = oval.find(".//*[@id='" + criterion.get("test_ref") + "']")
						ruledict["tests"].append( node_to_dict(ovaltest, include_type=True, oval=oval) )

	# make a nice directory name for the rule
	r = rule.get('id')
	r = re.sub('^xccdf_org\.(.*)\.content_rule_(.*)$', r'\1_\2', r)
	if drop_id_prefix and r.startswith(drop_id_prefix): r = r[len(drop_id_prefix):]
	if r == "group":
		# name clash with group.yaml
		r += "_rule"

	fn = os.path.join(*([outdir] + group_path + [r + '.yaml']))
	os.makedirs(os.path.dirname(fn), exist_ok=True)
	with open(fn, "w") as f:
		rtyaml.dump(ruledict, f)

	return r

oval_files = { }
def load_oval_file(src_path, href):
	# Load a referenced OVAL file and cache it since it will be
	# references many times.
	global oval_files
	ovalpath = os.path.join(os.path.dirname(src_path), href)
	if ovalpath not in oval_files:
		oval_files[ovalpath] = lxml.etree.parse(ovalpath).getroot()
	return oval_files[ovalpath]

def node_to_dict(node, include_type=False, oval=None):
	# get attributes, minus any recognized data type and any attributes we don't want
	exclude_attrs1 = ["id"] # we will regenerate all IDs during export
	exclude_attrs2 = [('datatype', 'int'), ('datatype', 'string'), ('datatype', 'boolean')]
	attrs = [kv for kv in node.items() if kv[0] not in exclude_attrs1 and kv not in exclude_attrs2]

	# get the element children; excludes comments
	children = [n for n in node if isinstance(n.tag, str)]

	# get the node's "value", if applicable
	if node.text is None or node.text.strip() == "":
		node_value = None
	else:
		node_value = node.text
		if node.get("datatype") == "int":
			node_value = int(node_value)
		if node.get("datatype") == "boolean":
			node_value = (node_value == "true")

	# if the node has no attributes (besides datatype) and no children,
	# just represent the value directly
	if len(attrs) == 0 and len(children) == 0 and not include_type:
		# No attributes or children. Just a value.
		return node_value

	# otherwise represent the node as a dict
	else:
		ret = collections.OrderedDict()

		if include_type:
			# Include the node's element as its type.
			ret["type"] = get_simple_tag_name(node.tag)

		# Attributes (with datatype removed).
		for k, v in sorted(attrs):
			# Turn namespaced names into QNames.
			k = get_simple_tag_name(k)

			# Anything that might be interpreted during export as something
			# other than an attribute should get @-escaped to make sure it
			# is recognized as an attribute.
			if ":" in k or "{" in k or k in ("type", "value"): k = "@" + k

			ret[k] = v

		if len(children) == 0:
			# No children; use value for the text content. Omit if null
			# and there are other attributes already set.
			if len(ret) == 0 or node_value is not None:
				ret["value"] = node_value
		else:
			# Serialize children.
			for child in children:
				tag = get_simple_tag_name(child.tag)
				child_include_type = False

				# Ensure that tags would not be mistaken for attributes.
				if (":" not in tag and "{" not in tag) or tag in ("type", "value"): tag = "<" + tag + ">"

				# Resolve OVAL references.
				for key in ("object", "state"):
					if child.get(key + "_ref") and oval is not None:
						child = oval.find('.//*[@id="' + child.get(key + "_ref") +'"]')
						child_include_type = True
						tag = key
						if child.tag == node.tag.replace("_test", "_" + key):
							child_include_type = False
				if child.tag == '{http://oval.mitre.org/XMLSchema/oval-definitions-5}filter':
					tag = 'filter'
					child = oval.find('.//*[@id="' + child.text +'"]')

				# Add the child.
				ret[tag] = node_to_dict(child, oval=oval, include_type=child_include_type)

	return ret

if __name__ == "__main__":
	main()
