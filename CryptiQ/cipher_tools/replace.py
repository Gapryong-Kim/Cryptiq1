def replace(text, to_replace, replacement):
    if not to_replace:
        return text
    return text.replace(to_replace, replacement)
