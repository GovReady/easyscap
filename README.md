easyscap
========

A simple (but equivalent) format for writing SCAP tests by [GovReady](http://www.govready.org/).

Security Content Automation Protocol (SCAP) is a set of standards for automated security auditing of computer systems. But writing SCAP tests is a pain. The XCCDF and OVAL formats are cumbersome. `easyscap` is a YAML-based representation format for SCAP tests that can be converted into and out of XCCDF 1.2 and OVAL 5.

Installing (Ubuntu 14.04)
-------------------------

Before using `easyscap`, you'll need to install prerequisities:

	sudo apt-get install python3 python3-pip pandoc 
	sudo pip3 install rtyaml

Importing from XCCDF/OVAL
-------------------------

`easyscap` converts XCCDF 1.2 and OVAL into YAML, and vice-versa. To demonstrate converting into YAML, we'll use the [Red Hat Enterprise Linux SCAP Security Guide (SSG)](https://fedorahosted.org/scap-security-guide/), which provides test definitions for Red Hat Enterprise Linux. An XCCDF 1.2 file contains the descriptions of tests and several profiles for which tests to run on which systems. It references an OVAL file which defines how the tests are to be executed by a SCAP implementation.

Let's convert the SSG into `easyscap`. Actually even SSG doesn't use XCCDF and OVAL directly! They build their XCCDF and OVAL file from small, broken-out XML files. But for this example we'll do the conversion from their complete XCCDF and OVAL files, so you'll need to compile their XCCDF and OVAL files first:

	sudo apt-get install git wget unzip libopenscap8 expat xsltproc
	git clone git://git.fedorahosted.org/git/scap-security-guide.git
	cd scap-security-guide
	make rhel6

Now run our import script to convert `ssg-rhel6-xccdf-1.2.xml` and `ssg-rhel6-oval.xml` into YAML:

	./import.py scap-security-guide/RHEL/6/output/ssg-rhel6-xccdf-1.2.xml easy-ssg

Note that the OVAL file is not specified on the command line. It is referenced inside the XCCDF file and we locate it automatically.

This saves the test definitions into a number of files in a directory tree rooted at `easy-ssg`. There are two sorts of files created: group files (all named `group.yaml`) and rule files.

Group files look like this (this is adapted from `output/ssgproject_services/ssh/group.yaml`):
	
	id: xccdf_org.ssgproject.content_group_ssh
	title: SSH Server
	description: |
	  The SSH protocol is recommended for remote login and remote file
	  transfer. SSH provides confidentiality and integrity for data exchanged
	  between two systems, as well as server authentication, through the use
	  of public key cryptography.

	  The implementation included with the system is called OpenSSH, and more
	  detailed documentation is available from its website, http://www.openssh.org.
	  Its server program is called `sshd` and provided by the RPM package
	  `openssh-server`.
	rules:
	- ssh_server_disabled
	- ssh_server_iptables_exception
	subgroups:
	- ssh_server


The `description` field (and `rationale` if present) is a Markdown string. The `|` character at the start of the field indicates a YAML literal block follows.

The list of `subgroups` references other `group.yaml` files in subdirectories. The list of `rules` references `.yaml` files located in the same directory.

The file `ssh_server_iptables_exception.yaml` in the same directory looks like this:

	id: xccdf_org.ssgproject.content_rule_ssh_server_iptables_exception
	severity: low
	title: Remove SSH Server iptables Firewall exception (Unusual)
	description: |
	  By default, inbound connections to SSH’s port are allowed. If the SSH
	  server is not being used, this exception should be removed from the
	  firewall configuration.
	rationale: |
	  If inbound SSH connections are not expected, disallowing access to the
	  SSH port will avoid possible exploitation of the port by an attacker.
	tests:
	- type: ind:textfilecontent54_test
	  check: all
	  check_existence: none_exist
	  object:
	    ind:path: /etc/sysconfig
	    ind:filename: iptables
	    ind:pattern:
	      operation: pattern match
	      value: ^-A INPUT -m state --state NEW -m tcp -p tcp --dport 25 -j ACCEPT$
	    ind:instance: 1

The metadata (id, title, description, etc) is similar to that of groups. But rules have a `severity` field and a `tests` field which lists the tests that are run as a part of this rule. The tests are a 1-to-1 mapping from the OVAL test definitions in SSG. You will need to read the OVAL specification to see how to specify tests.

Exporting YAML to XCCDF/OVAL
----------------------------

We'll now convert the YAML back to OVAL. (Exporting to XCCDF is not yet implemented.)

	./export.py easy-ssg/group.yaml output-oval.xml

This writes `output-oval.xml`. Then try running the tests in the file:

	oscap oval eval output-oval.xml

