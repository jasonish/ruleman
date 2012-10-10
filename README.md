RULEMAN (Rule Manager)
======================

Ruleman is a tool to manager your SNORT(R) and/or Suricata rules.

WARNING
-------

This is a gathering of scripts I've used to manage my personal IDS
deployment and is attempt to clean them up and give them a consistent
feel.  As such, the commands, and files used by this program may
change drastically.

REQUIREMENTS
------------

Ruleman only depends on a standard installation of Python 2.6 or
Python 2.7.  It currently does not run on Python 3.

INSTALLATION
------------

While ruleman does not require installation to work properly, it can
be installed like so:

    python setup.py build

    sudo python setup.py install
    
Installing it will make it available on the standard.

Alternatively you could call ruleman using the full path to the
ruleman program or put the ruleman project directory on your path or
create a shell alias.

USAGE
-----

### Initialize a Ruleman Working Directory

Before ruleman can be used it needs a set of configuration files.
These files can be created for you using the "init" command:

    ruleman init [dir]
	
If [dir] is not provided the current directory will be initialized as
a ruleman working directory.

### Configuration

Before continuuing you will need to edit ruleman.conf.  You will need
to add at least one [ruleset <name>] configuration as well as a
profile section.

### Fetching Rules

The fetch command will only fetch the rules without deploying them:

    ruleman fetch

### Deploying Rules

To deploy rules without doing a fetch run the deploy command:

	ruleman deploy
	
### Fetching and Deploying Rules

To fetch and deploy the rules using a single command:
    
	ruleman update

OTHER NOTES
-----------
- The rules for a profile are deployed to the directory
  ./profiles/default.  I may add support for multiple profiles in
  which case 'default' will be replaced with the profile name.

- If a profile contains an "os-type" parameter, ruleman will attempt
  to create a symlink named "dynamicrules" in the root of the deployed
  profile directory to the directory containing the dynamic rules for
  that OS type and Snort version.

- The configuration file is based on Python's ConfigParser module, so
  can use all the features provided by it.
  
- Rule modifications are performed in the following order:

  - disable rules
  - enable rules
  - drop rules
  
  Making the order configurable may be an option in the future.
  
- There is currently no way to modify rules.

