import re

FB_TOKENIZE_PATTERN = re.compile("[,&|]")

def get_required_flowbits(ruleset):
    """ Return a set of all the required flowbits for enabled rules.

    The argument ruleset is a dict of filenames (groups) that contains
    a list of Rule objects.
    """
    required = set()
    for group in ruleset:
        for rule in ruleset[group]:
            if rule.enabled and rule.flowbits:
                for fb in rule.flowbits:
                    tokens = FB_TOKENIZE_PATTERN.split(fb)
                    if tokens[0] in ["isset", "isnotset"]:
                        for bit in tokens[1:]:
                            required.add(bit)
    return required

def set_required_flowbits(ruleset, required):
    """ Make sure all rules that may set or unset a required flowbit
    is enabled.

    A list of the rules that were enabled is returned.
    """
    enabled = []
    for group in ruleset:
        for rule in ruleset[group]:
            if not rule.enabled and rule.flowbits:
                for fb in rule.flowbits:
                    tokens = FB_TOKENIZE_PATTERN.split(fb)
                    if tokens[0] in ["set", "setx", "unset", "reset"]:
                        if set(tokens[1:]).issubset(required):
                            rule.enabled = True
                            enabled.append(rule)
    return enabled

def resolve_dependencies(ruleset):
    enabled = []
    
    while True:
        required = get_required_flowbits(ruleset)
        _enabled = set_required_flowbits(ruleset, required)
        print("Enabled %d rules." % len(_enabled))
        if _enabled:
            enabled += _enabled
        else:
            break
    
    return enabled
