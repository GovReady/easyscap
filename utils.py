import re, subprocess
import lxml.etree

simple_namespaces = {
	'http://purl.org/dc/elements/1.1/': 'dc',
	'http://www.w3.org/2001/XMLSchema-instance': 'xsi',
	'http://checklists.nist.gov/xccdf/1.2': 'xccdf',
	'http://oval.mitre.org/XMLSchema/oval-definitions-5#independent': 'ind',
	'http://oval.mitre.org/XMLSchema/oval-definitions-5#linux': 'linux',
	'http://oval.mitre.org/XMLSchema/oval-definitions-5#unix': 'unix',
}
simple_namespaces_inv = { v: k for (k, v) in simple_namespaces.items()}

def get_simple_tag_name(tag):
	def get_namespace_prefix(match):
		if match.group(1) in simple_namespaces:
			return simple_namespaces[match.group(1)] + ":"
		else:
			return match.group(0)
	return re.sub(r"^{(.*)}", get_namespace_prefix, tag)

def expand_tag_name(tag):
	if tag[0] == "{" or ":" not in tag: return tag
	prefix, localname = tag.split(":", 1)
	if prefix not in simple_namespaces_inv: return tag
	return "{%s}%s" % (simple_namespaces_inv[prefix], localname)

def pandoc(text, fromformat, toformat):
	if text is None: return None

	if fromformat == "html":
		# Get the "innerHTML" of an lxml.etree element if we are passed an element.
		if isinstance(text, lxml.etree._Element):
			# XCCDF text may have namespaced XHTML tags. Pandoc doesn't recognize this.
			for child in text.findall(".//*"):
				child.tag = re.sub(r'^{http://www.w3.org/1999/xhtml}', '{}', child.tag)

			# Get the innerHTML of the node.
			text = (text.text if text.text else "") + ''.join([lxml.etree.tostring(child, method='html', encoding=str) for child in text.iterchildren()])

			# Also remove any xmlns:xhtml namespaces which muck up Markdown. Not sure how to do that properly.
			text = text.replace(' xmlns="http://www.w3.org/1999/xhtml"', '')
			text = text.replace(' xmlns:xhtml="http://www.w3.org/1999/xhtml"', '')
			text = text.replace(' xmlns="http://checklists.nist.gov/xccdf/1.2"', '')
			text = re.sub("(\s*<br>\s*){2,}", "<p>", text)

	if text.strip() == "": return None

	with subprocess.Popen([
    	"pandoc",
    	"-f", fromformat,
    	"-t", toformat,
    	"--normalize", # merge elements
    	"-R", # preserve unknown HTML in Markdown output
    	"-S", # smart HTML output like curly quotes
    ],
    	stdin=subprocess.PIPE,
    	stdout=subprocess.PIPE) as proc:
		outs, errs = proc.communicate(text.encode("utf8"))
		ret = outs.decode("utf8").strip()

	# For YAML's benefit, add a newline at the end if the string contains any
	# newlines. This prevents YAML from adding a chomping "strip" indicator.
	if "\n" in ret.rstrip():
		ret += "\n"

	return ret

