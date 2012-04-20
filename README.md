RULEMAN (Rule Manager)
======================

Ruleman is a tool to manager your SNORT(R) and/or Suricata rules.

WARNING
-------

This is a gathering of scripts I've used to manage my personal IDS
deployment and is attempt to clean them up and give them a consistent
feel.  As such, the commands, and files used by this program may
change drastically.

QUICKSTART
----------

* Unpack the distribution archive or clone ruleman from the git
  repository. 

* Create a directory to store your configuration and data files in.

  - mkdir ruleman-data
  - /path/to/ruleman init
  
* Modify ruleman.conf to meet your needs.  Note that Snort specific
  parameters are only required for SO stub generation which you may
  not need to do.

INSTALLATION
------------

While ruleman does not require installation to work properly, it can
be installed like so:

    python setup.py build
    sudo python setup.py install
    
An alternative to installation is to just create a shell alias to
alias "ruleman" to the full path of where you expanded (or checked
out) the ruleman distribution.

USAGE
-----

Ruleman expects to be run from the directory containing ruleman.conf.

To download and export rules for each profile:

    /path/to/ruleman update
    
To just download the rulesets:

    /path/to/ruleman fetch

To export the rules for each profile:

    /path/to/ruleman export
  
To search for a rule (requires that a fetch has already been done):

    /path/to/ruleman search

TODO and IDEAS
--------------
- Allow a profile to be listed in place of rulesets in a given profile
  to allow a sort of inheritance.
- Support for local files.
- Command for changing configuration (like git config).
  - NOTE: Will probably lose the ability to comment the config file if
    a tool is modifying it.
- Post export hooks.
- Cache regenerated SO rule stubs as part of the fetch phase do avoid
  regeneration when just exporting the rules after a change such as an
  enable/disable.
- Pack the output of a profile into a .tar.gz.
- Users supplied rule transformations..
  - Keep it simple, user supplies a function that each rule is passed
    to, and the function can decide to modify it or not.
- Purge old downloaded rulesets after a time period or file count.
- Ability to set latest back to an older ruleset.
- Move from multiple instruction files (eg. enable-rules,
  disable-rules) to a single file where each line is prefixed with an
  instruction type.
- Disable/enable rules based on a regex.
- Command to disable/enable rules.
  - Logs a reason, and a date of the modification.
- Initial setup wizard.
